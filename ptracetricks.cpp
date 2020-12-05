#include <filesystem>
#include <iostream>
#include <cstring>
#include <memory>
#include <vector>
#include <cinttypes>
#include <array>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/uio.h>
#include <boost/format.hpp>
#include <boost/dynamic_bitset.hpp>
#include <unordered_map>
#include <getopt.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)   __builtin_expect(!!(x), 0)
#endif

namespace fs = std::filesystem;

//using llvm::WithColor;

using namespace std;

namespace opts {

static std::string Prog;
static std::vector<std::string> Args;
static std::vector<std::string> Envs;
static bool Verbose;
static bool Syscalls;
static unsigned PID;
static std::vector<const char *> Breakpoints;

} // namespace opts

namespace ptracetricks {

typedef std::pair<std::string, uintptr_t> breakpoint_t;

static std::unordered_map<uintptr_t, unsigned> BreakpointPCMap;
static std::vector<breakpoint_t> Breakpoints;
static std::vector<long> BreakpointsInsnWord;

static int ChildProc(void);
static int TracerLoop(pid_t child);

static bool SeenExec = false;

static void IgnoreCtrlC(void) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = SIG_IGN;

  if (sigaction(SIGINT, &sa, nullptr) < 0) {
    int err = errno;
    cerr << "sigaction failed (" << strerror(err) << ")\n";
  }
}

#define _NORET __attribute__((noreturn))

static _NORET void usage() {
  cout << "Usage:\n"
          "ptracetricks [OPTIONS] PROG -- [ARG_1] [ARG_2] ... [ARG_n]\n"
          "or\n"
          "ptracetricks [OPTIONS] --attach PID\n"
          "\n"
          "Options:\n"
          "  --help (-h)\n"
          "  --version (-V)\n"
          "  --verbose (-v)\n"
          "  --syscalls (-s)\n"
          "  --breakpoint (-b) /path/to/dso+RVA\n"
          "  --attach (-p) PID\n";
  exit(0);
}

static _NORET void version(void) {
#ifndef PTRACETRICKS_VERSION
#error
#endif

  cout << "version " PTRACETRICKS_VERSION << endl;
  exit(0);
}

} // namespace ptracetricks

int main(int argc, char **argv) {
  int _argc = argc;
  char **_argv = argv;

  // argc/argv replacement to handle '--'
  struct {
    std::vector<std::string> s;
    std::vector<const char *> a;
  } arg_vec;

  {
    int prog_args_idx = -1;

    for (int i = 0; i < argc; ++i) {
      if (strcmp(argv[i], "--") == 0) {
        prog_args_idx = i;
        break;
      }
    }

    if (prog_args_idx != -1) {
      for (int i = 0; i < prog_args_idx; ++i)
        arg_vec.s.push_back(argv[i]);

      for (std::string &s : arg_vec.s)
        arg_vec.a.push_back(s.c_str());
      arg_vec.a.push_back(nullptr);

      _argc = prog_args_idx;
      _argv = const_cast<char **>(&arg_vec.a[0]);

      for (int i = prog_args_idx + 1; i < argc; ++i) {
        opts::Args.push_back(argv[i]);
      }
    }
  }

  static struct option const longopts[] =
  {
    {"syscalls",   no_argument,       NULL, 's'},
    {"verbose",    no_argument,       NULL, 'v'},
    {"attach",     required_argument, NULL, 'p'},
    {"breakpoint", required_argument, NULL, 'b'},
    {"help",       no_argument,       NULL, 'h'},
    {"version",    no_argument,       NULL, 'V'},
    {NULL, 0, NULL, 0}
  };

  int optc;
  while ((optc = getopt_long(_argc, _argv, "shvVb:p:", longopts, NULL)) != -1) {
    switch (optc) {
    case 's':
      opts::Syscalls = true;
      break;

    case 'p':
      assert(optarg);
      opts::PID = atoi(optarg);
      assert(opts::PID);
      break;

    case 'b':
      assert(optarg);
      opts::Breakpoints.push_back(optarg);
      break;

    case 'v':
      opts::Verbose = true;
      break;

    case 'V':
      ptracetricks::version();

    case 'h':
    default:
      ptracetricks::usage();
    }
  }

  if (!opts::PID && opts::Prog.empty()) {
    for (int index = optind; index < _argc; index++) {
      //printf("Non-option argument %s\n", _argv[index]);
      opts::Prog = _argv[index];
      break;
    }
  }

  //
  // process breakpoints from command-line
  //
  auto is_valid_breakpoint_string = [](const std::string& s) -> bool {
    if (s.empty())
      return false;

    if (s.find('+') == std::string::npos)
      return false;

    return true;
  };

  for (const char *bp : opts::Breakpoints) {
    if (!is_valid_breakpoint_string(bp)) {
      std::cerr << "warning: given breakpoint string is invalid; ignoring\n";
      continue;
    }

    std::string s(bp);

    std::string::size_type plusPos = s.find('+');
    assert(plusPos != std::string::npos);

    std::string L = s.substr(0,plusPos); /* DSO path */
    std::string R = s.substr(plusPos+1); /* hexadecimal number */

    if (!fs::exists(L)) {
      std::cerr << "warning: given DSO in breakpoint string does not exist; ignoring\n";
      continue;
    }

    uintptr_t rva = std::stol(R, nullptr, 0x10);

    ptracetricks::Breakpoints.emplace_back(L, rva);
  }

  ptracetricks::BreakpointsInsnWord.resize(ptracetricks::Breakpoints.size());

  /* Line buffer stdout to ensure lines are written atomically and immediately
     so that processes running in parallel do not intersperse their output.  */
  setvbuf(stdout, NULL, _IOLBF, 0);

  //
  // ptracetricks has two modes of execution.
  //
  // (1) Trace existing process (--attach pid)
  // (2) Trace newly created process (PROG -- ARG_1 ARG_2 ... ARG_N)
  //
  if (pid_t child = opts::PID) {
    //
    // mode 1: attach
    //
    if (ptrace(PTRACE_ATTACH, child, 0, 0) < 0) {
      cerr << "PTRACE_ATTACH failed (" << strerror(errno) << ")\n";
      return 1;
    }

    //
    // since PTRACE_ATTACH succeeded, we know the tracee was sent a SIGSTOP.
    // wait on it.
    //
    {
      int status;
      do
        waitpid(-1, &status, __WALL);
      while (!WIFSTOPPED(status));
    }

    ptracetricks::SeenExec = true; /* XXX */
    return ptracetricks::TracerLoop(child);
  } else {
    //
    // mode 2: exec
    //
    if (!fs::exists(opts::Prog.c_str())) {
      cerr << "given program does not exist";
      return 1;
    }

    child = fork();
    if (!child)
      return ptracetricks::ChildProc();

    //
    // observe the (initial) signal-delivery-stop
    //
    cerr << "parent: waiting for initial stop of child " << child << "...\n";

    {
      int status;
      do
        waitpid(child, &status, 0);
      while (!WIFSTOPPED(status));
    }

    cerr << "parent: initial stop observed\n";

    ptracetricks::IgnoreCtrlC(); /* XXX */

    return ptracetricks::TracerLoop(child);
  }
}

namespace ptracetricks {

#if defined(__mips__) || defined(__arm__)
typedef struct pt_regs cpu_state_t;
#else
typedef struct user_regs_struct cpu_state_t;
#endif

static void _ptrace_get_cpu_state(pid_t, cpu_state_t &out);
static void _ptrace_set_cpu_state(pid_t, const cpu_state_t &in);

static std::string _ptrace_read_string(pid_t, uintptr_t addr);

static unsigned long _ptrace_peekdata(pid_t, uintptr_t addr);
static void _ptrace_pokedata(pid_t, uintptr_t addr, unsigned long data);

static ssize_t _ptrace_memcpy(pid_t, void *dest, const void *src, size_t n);

static void print_command(std::vector<const char *> &arg_vec);

namespace syscalls {

constexpr unsigned NR_MAX = std::max<unsigned>({0u

#define SYSCALL_DEFINE(nr, nm) ,nr
#include "syscalls.inc.h"

                            }) +
                            1u;
namespace NR {
#define SYSCALL_DEFINE(nr, nm) constexpr unsigned nm = nr;
#include "syscalls.inc.h"
} // namespace NR
} // namespace syscalls

static const char *syscall_names[syscalls::NR_MAX] = {
    [0 ... syscalls::NR_MAX - 1] = nullptr,

#define SYSCALL_DEFINE(nr, nm) [nr] = #nm,
#include "syscalls.inc.h"
};

struct child_syscall_state_t {
  unsigned no;
  long a1, a2, a3, a4, a5, a6;
  unsigned int dir : 1;

  unsigned long pc;

  child_syscall_state_t() : dir(0), pc(0) {}
};

static std::unordered_map<pid_t, child_syscall_state_t> children_syscall_state;

static void
PlantBreakpoint(unsigned Idx, pid_t,
                const std::unordered_map<std::string, uintptr_t> &vmm);
static bool executable_virtual_memory_mappings_for_process(
    pid_t child, std::unordered_map<std::string, uintptr_t> &out);

static void on_breakpoint(unsigned Idx, pid_t, const cpu_state_t &);

static long pc_of_cpu_state(const cpu_state_t &cpu_state) {
  long pc =
#if defined(__x86_64__)
      cpu_state.rip
#elif defined(__i386__)
      cpu_state.eip
#elif defined(__aarch64__)
      cpu_state.pc
#elif defined(__arm__)
      cpu_state.uregs[15]
#elif defined(__mips64) || defined(__mips__)
      cpu_state.cp0_epc
#else
#error
#endif
      ;

  return pc;
}

int TracerLoop(pid_t child) {
  boost::dynamic_bitset<> BreakpointsPlanted;
  BreakpointsPlanted.resize(Breakpoints.size());

  //
  // select ptrace options
  //
  int ptrace_options = PTRACE_O_TRACESYSGOOD
                     | PTRACE_O_TRACECLONE
                     | PTRACE_O_TRACEEXEC
                     | PTRACE_O_TRACEFORK
                     | PTRACE_O_TRACEVFORK;

  /* PTRACE_O_EXITKILL */

  //
  // set those options
  //
  if (ptrace(PTRACE_SETOPTIONS, child, 0, ptrace_options) < 0) {
    cerr << "PTRACE_SETOPTIONS failed (" << strerror(errno) << ')' << endl;
    return 1;
  }

  siginfo_t si;
  long sig = 0;

  try {
    for (;;) {
      if (likely(!(child < 0))) {
        if (unlikely(
                ptrace(SeenExec && (opts::Syscalls || !BreakpointsPlanted.all())
                           ? PTRACE_SYSCALL
                           : PTRACE_CONT,
                       child, nullptr, reinterpret_cast<void *>(sig)) < 0))
          cerr << "failed to resume tracee : " << strerror(errno) << '\n';
      }

      //
      // reset restart signal
      //
      sig = 0;

      //
      // wait for a child process to stop or terminate
      //
      int status;
      child = waitpid(-1, &status, __WALL);

      if (unlikely(child < 0)) {
        cerr << "exiting... (" << strerror(errno) << ")\n";
        break;
      }

      if (likely(WIFSTOPPED(status))) {
        //
        // if we need to plant breakpoints, this is an opprtunity to do so
        //
        if (SeenExec && !BreakpointsPlanted.all()) {
          //
          // parse /proc/<child>/maps
          //
          std::unordered_map<std::string, uintptr_t> vmm;
          if (executable_virtual_memory_mappings_for_process(child, vmm)) {
            for (unsigned Idx = 0; Idx < BreakpointsPlanted.size(); ++Idx) {
              if (BreakpointsPlanted.test(Idx))
                continue;

              try {
                PlantBreakpoint(Idx, child, vmm);

                BreakpointsPlanted.set(Idx);
              } catch (const std::exception &ex) {
                if (opts::Verbose)
                  std::cerr << "failed to plant breakpoint: " << ex.what()
                            << '\n';
              }
            }
          }
        }

        //
        // the following kinds of ptrace-stops exist:
        //
        //   (1) syscall-stops
        //   (2) PTRACE_EVENT stops
        //   (3) group-stops
        //   (4) signal-delivery-stops
        //
        // they all are reported by waitpid(2) with WIFSTOPPED(status) true.
        // They may be differentiated by examining the value status>>8, and if
        // there is ambiguity in that value, by querying PTRACE_GETSIGINFO.
        // (Note: the WSTOPSIG(status) macro can't be used to perform this
        // examination, because it returns the value (status>>8) & 0xff.)
        //
        const int stopsig = WSTOPSIG(status);
        if (stopsig == (SIGTRAP | 0x80)) {
          //
          // (1) Syscall-enter-stop and syscall-exit-stop are observed by the
          // tracer as waitpid(2) returning with WIFSTOPPED(status) true, and-
          // if the PTRACE_O_TRACESYSGOOD option was set by the tracer- then
          // WSTOPSIG(status) will give the value (SIGTRAP | 0x80).
          //
          child_syscall_state_t &syscall_state = children_syscall_state[child];

          cpu_state_t cpu_state;
          _ptrace_get_cpu_state(child, cpu_state);

          long pc = pc_of_cpu_state(cpu_state);

          //
          // determine whether this syscall is entering or has exited
          //
#if defined(__arm__)
          unsigned dir = cpu_state.uregs[12]; /* unambiguous */
#else
          unsigned dir = syscall_state.dir;

          if (syscall_state.pc != pc)
            dir = 0; /* we must see the same pc twice */
#endif

          if (dir == 0 /* enter */) {
            //
            // store the arguments and syscall #
            //
#if defined(__x86_64__)
            long no = cpu_state.orig_rax;

            long a1 = cpu_state.rdi;
            long a2 = cpu_state.rsi;
            long a3 = cpu_state.rdx;
            long a4 = cpu_state.r10;
            long a5 = cpu_state.r8;
            long a6 = cpu_state.r9;
#elif defined(__i386__)
            long no = cpu_state.orig_eax;

            long a1 = cpu_state.ebx;
            long a2 = cpu_state.ecx;
            long a3 = cpu_state.edx;
            long a4 = cpu_state.esi;
            long a5 = cpu_state.edi;
            long a6 = cpu_state.ebp;
#elif defined(__aarch64__)
            long no = cpu_state.regs[8];

            long a1 = cpu_state.regs[0];
            long a2 = cpu_state.regs[1];
            long a3 = cpu_state.regs[2];
            long a4 = cpu_state.regs[3];
            long a5 = cpu_state.regs[4];
            long a6 = cpu_state.regs[5];
#elif defined(__arm__)
            long no = cpu_state.uregs[7];

            long a1 = cpu_state.uregs[0];
            long a2 = cpu_state.uregs[1];
            long a3 = cpu_state.uregs[2];
            long a4 = cpu_state.uregs[3];
            long a5 = cpu_state.uregs[4];
            long a6 = cpu_state.uregs[5];
#elif defined(__mips64)
            long no = cpu_state.regs[2];

            long a1 = cpu_state.regs[4];
            long a2 = cpu_state.regs[5];
            long a3 = cpu_state.regs[6];
            long a4 = cpu_state.regs[7];
            long a5 = cpu_state.regs[8];
            long a6 = cpu_state.regs[9];
#elif defined(__mips__)
            long no = cpu_state.regs[2];

            long a1 = cpu_state.regs[4];
            long a2 = cpu_state.regs[5];
            long a3 = cpu_state.regs[6];
            long a4 = cpu_state.regs[7];
            long a5 = _ptrace_peekdata(child, cpu_state.regs[29 /* sp */] + 16);
            long a6 = _ptrace_peekdata(child, cpu_state.regs[29 /* sp */] + 20);
#else
#error
#endif

            syscall_state.no = no;
            syscall_state.a1 = a1;
            syscall_state.a2 = a2;
            syscall_state.a3 = a3;
            syscall_state.a4 = a4;
            syscall_state.a5 = a5;
            syscall_state.a6 = a6;
          } else { /* exit */
            auto &ret =
#if defined(__x86_64__)
                cpu_state.rax
#elif defined(__i386__)
                cpu_state.eax
#elif defined(__aarch64__)
                cpu_state.regs[0]
#elif defined(__arm__)
                cpu_state.uregs[0]
#elif defined(__mips64) || defined(__mips__)
                cpu_state.regs[2]
#else
#error
#endif
                ;

            long no = syscall_state.no;

            long a1 = syscall_state.a1;
            long a2 = syscall_state.a2;
            long a3 = syscall_state.a3;
            long a4 = syscall_state.a4;
            long a5 = syscall_state.a5;
            long a6 = syscall_state.a6;

            auto print_syscall = [&](std::ostream &out) -> void {
              const char *const nm = syscall_names[no];

              //
              // print syscall
              //
              out << nm << '(';

              //
              // print arguments
              //
              try {
                switch (no) {
                case syscalls::NR::openat:
                  out << dec << a1 << ", \"" << _ptrace_read_string(child, a2) << '\"';
                  break;
                case syscalls::NR::access:
                  out << '\"' << _ptrace_read_string(child, a1) << "\", " << std::dec << a2;
                  break;
                case syscalls::NR::close:
                  out << std::dec << a1;
                  break;
                case syscalls::NR::exit_group:
                  out << std::dec << a1;
                  break;
                case syscalls::NR::fstat64:
                  out << std::dec << a1 << ", " << "0x" << std::hex << a2;
                  break;
                case syscalls::NR::stat64:
                  out << '\"' << _ptrace_read_string(child, a1) << "\", 0x" << std::hex << a2;
                  break;
                case syscalls::NR::clock_settime:
                case syscalls::NR::clock_gettime:
                  out << std::dec << a1 << ", " << "0x" << std::hex << a2;
                  break;
                case syscalls::NR::recv:
                case syscalls::NR::readv:
                case syscalls::NR::read:
                case syscalls::NR::writev:
                case syscalls::NR::write:
                  out << std::dec << a1 << ", 0x" << std::hex << a2 << ", " << std::dec << a3;
                  break;
                case syscalls::NR::brk:
                  out << "0x" << std::hex << a1;
                  break;
                case syscalls::NR::mprotect:
                  out << "0x" << std::hex << a1 << ", " << std::dec << a2 << ", " << a3;
                  break;
                case syscalls::NR::mmap2:
                  out << "0x" << std::hex << a1 << ", " << std::dec << a2 << ", " << a3 << ", " << a4 << ", " << a5 << ", " << a6;
                  break;
                case syscalls::NR::munmap:
                  out << "0x" << std::hex << a1 << ", " << std::dec << a2;
                  break;
                case syscalls::NR::prctl:
                  out << std::dec
                       << a1 << ", "
                       << a2 << ", "
                       << a3 << ", "
                       << a4 << ", "
                       << a5;
                  break;
                }
              } catch (...) {
              }

              bool IsRetPointer = false;
              switch (no) {
              case syscalls::NR::brk:
              case syscalls::NR::mmap2:
                IsRetPointer = true;
                break;

              default:
                break;
              }

              out << ") = ";

              if (IsRetPointer)
                out << "0x" << std::hex << ret;
              else
                out << std::dec << ret;

              out << '\n';
            };

            if (opts::Syscalls &&
                no >= 0 &&
                no < syscalls::NR_MAX &&
                syscall_names[no])
              print_syscall(std::cout);
          }

          dir ^= 1;

          syscall_state.pc = pc;
          syscall_state.dir = dir;
        } else if (stopsig == SIGTRAP) {
          const unsigned int event = (unsigned int)status >> 16;

          //
          // PTRACE_EVENT stops (2) are observed by the tracer as waitpid(2)
          // returning with WIFSTOPPED(status), and WSTOPSIG(status) returns
          // SIGTRAP.
          //
          if (unlikely(event)) {
            switch (event) {
            case PTRACE_EVENT_VFORK:
              cerr << "ptrace event (PTRACE_EVENT_VFORK) [" << child << "]\n";
              break;
            case PTRACE_EVENT_FORK:
              cerr << "ptrace event (PTRACE_EVENT_FORK) [" << child << "]\n";
              break;
            case PTRACE_EVENT_CLONE: {
              pid_t new_child;
              ptrace(PTRACE_GETEVENTMSG, child, nullptr, &new_child);

              cerr << "ptrace event (PTRACE_EVENT_CLONE) -> " << new_child << " [" << child << "]\n";
              break;
            }
            case PTRACE_EVENT_VFORK_DONE:
              cerr << "ptrace event (PTRACE_EVENT_VFORK_DONE) [" << child << "]\n";
              break;
            case PTRACE_EVENT_EXEC:
              cerr << "ptrace event (PTRACE_EVENT_EXEC) [" << child << "]\n";

              SeenExec = true;
              break;
            case PTRACE_EVENT_EXIT:
              cerr << "ptrace event (PTRACE_EVENT_EXIT) [" << child << "]\n";
              break;
#ifdef PTRACE_EVENT_STOP
            case PTRACE_EVENT_STOP:
              cerr << "ptrace event (PTRACE_EVENT_STOP) [" << child << "]\n";
              break;
#endif
            case PTRACE_EVENT_SECCOMP:
              cerr << "ptrace event (PTRACE_EVENT_SECCOMP) [" << child << "]\n";
              break;
            }
          } else {
            //
            // did we hit a breakpoint?
            //
            cpu_state_t cpu_state;
            _ptrace_get_cpu_state(child, cpu_state);

            long pc = pc_of_cpu_state(cpu_state);

            auto it = BreakpointPCMap.find(pc);
            if (it == BreakpointPCMap.end()) {
              std::cerr << "warning: no breakpoint @ " << std::hex << pc
                        << std::endl;
            } else {
              on_breakpoint((*it).second, child, cpu_state);
            }
          }
        } else if (ptrace(PTRACE_GETSIGINFO, child, 0, &si) < 0) {
          //
          // (3) group-stop
          //

          cerr << "ptrace group-stop [" << child << "]\n";

          // When restarting a tracee from a ptrace-stop other than
          // signal-delivery-stop, recommended practice is to always pass 0 in
          // sig.
        } else {
          //
          // (4) signal-delivery-stop
          //
          cpu_state_t cpu_state;
          _ptrace_get_cpu_state(child, cpu_state);

          long pc = pc_of_cpu_state(cpu_state);

          if (stopsig == SIGILL &&
              BreakpointPCMap.count(pc)) {
            //
            // suppress the signal ; this is a breakpoint
            //
            on_breakpoint(BreakpointPCMap[pc], child, cpu_state);
          } else {
            //
            // deliver it
            //
            cerr << "delivering signal number " << stopsig << " [" << child << "]\n";

            sig = stopsig;
          }
        }
      } else {
        //
        // the child terminated
        //
        cerr << "child " << child << " terminated\n";

        child = -1;
      }
    }
  } catch (const std::exception &e) {
    cerr << "exception! " << e.what() << '\n';
  } catch (...) {
    cerr << "unknown exception!\n";
  }

  return 0;
}

static void dump_cpu_state(std::ostream &out, const cpu_state_t &);

void on_breakpoint(unsigned Idx, pid_t child, const cpu_state_t &cpu_state) {
  long pc = pc_of_cpu_state(cpu_state);

  if (opts::Verbose)
    std::cerr << "on_breakpoint @ " << std::hex << pc << std::endl;

  dump_cpu_state(std::cout, cpu_state);

  //
  // restore original instruction word
  //
  _ptrace_pokedata(child, pc, BreakpointsInsnWord.at(Idx));
}

void dump_cpu_state(std::ostream &out, const cpu_state_t &cpu_state) {
  out << '\n';

  char buff[0x1000];

#if defined(__arm__)
  snprintf(buff, sizeof(buff),
    "R00=%08lx R01=%08lx R02=%08lx R03=%08lx" "\n"
    "R04=%08lx R05=%08lx R06=%08lx R07=%08lx" "\n"
    "R08=%08lx R09=%08lx R10=%08lx R11=%08lx" "\n"
    "R12=%08lx R13=%08lx R14=%08lx R15=%08lx" "\n",

    cpu_state.uregs[0],  cpu_state.uregs[1],  cpu_state.uregs[2],  cpu_state.uregs[3],
    cpu_state.uregs[4],  cpu_state.uregs[5],  cpu_state.uregs[6],  cpu_state.uregs[7],
    cpu_state.uregs[8],  cpu_state.uregs[9],  cpu_state.uregs[10], cpu_state.uregs[11],
    cpu_state.uregs[12], cpu_state.uregs[13], cpu_state.uregs[14], cpu_state.uregs[15]);
#elif defined(__mips__)
  snprintf(buff, sizeof(buff),
    "r0" " %08x " "at" " %08x " "v0" " %08x " "v1" " %08x " "a0" " %08x " "a1" " %08x " "a2" " %08x " "a3" " %08x " "\n"
    "t0" " %08x " "t1" " %08x " "t2" " %08x " "t3" " %08x " "t4" " %08x " "t5" " %08x " "t6" " %08x " "t7" " %08x " "\n"
    "s0" " %08x " "s1" " %08x " "s2" " %08x " "s3" " %08x " "s4" " %08x " "s5" " %08x " "s6" " %08x " "s7" " %08x " "\n"
    "t8" " %08x " "t9" " %08x " "k0" " %08x " "k1" " %08x " "gp" " %08x " "sp" " %08x " "s8" " %08x " "ra" " %08x " "\n",

    cpu_state.regs[0],  cpu_state.regs[1],  cpu_state.regs[2],  cpu_state.regs[3],  cpu_state.regs[4],  cpu_state.regs[5],  cpu_state.regs[6],  cpu_state.regs[7],
    cpu_state.regs[8],  cpu_state.regs[9],  cpu_state.regs[10], cpu_state.regs[11], cpu_state.regs[12], cpu_state.regs[13], cpu_state.regs[14], cpu_state.regs[15],
    cpu_state.regs[16], cpu_state.regs[17], cpu_state.regs[18], cpu_state.regs[19], cpu_state.regs[20], cpu_state.regs[21], cpu_state.regs[22], cpu_state.regs[23],
    cpu_state.regs[24], cpu_state.regs[25], cpu_state.regs[26], cpu_state.regs[27], cpu_state.regs[28], cpu_state.regs[29], cpu_state.regs[30], cpu_state.regs[31]);
#else
#error
#endif

  out << buff;
  out << '\n';
}

bool executable_virtual_memory_mappings_for_process(
    pid_t child, std::unordered_map<std::string, uintptr_t> &out) {
  FILE *fp = nullptr;
  char *line = nullptr;

  {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", static_cast<int>(child));

    fp = fopen(path, "r");
  }

  if (!fp)
    return false;

  out.clear();

  size_t len = 0;
  ssize_t read;

  while ((read = getline(&line, &len, fp)) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line,
                    "%" PRIx64 "-%" PRIx64 " %c%c%c%c %" PRIx64 " %x:%x %d"
                    " %512s",
                    &min, &max, &flag_r, &flag_w, &flag_x, &flag_p, &offset,
                    &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11)) {
      continue;
    }

    bool r = flag_r == 'r';
    bool w = flag_w == 'w';
    bool x = flag_x == 'x';
    bool p = flag_p == 'p';

    if (x)
      out[path] = min + offset;
  }

  free(line);
  fclose(fp);

  return true;
}

static void arch_put_breakpoint(void *code);

void PlantBreakpoint(unsigned Idx,
                     pid_t child,
                     const std::unordered_map<std::string, uintptr_t> &vmm) {
  std::string dso;
  uintptr_t   rva;
  std::tie(dso, rva) = Breakpoints.at(Idx);

  //
  // parse /proc/<child>/maps
  //
  auto it = vmm.find(dso);
  if (it == vmm.end()) {
    throw std::runtime_error(
        std::string("PlantBreakpoint failed : could not find vmm for \"") +
        dso + std::string("\""));
  }

  uintptr_t va = rva + (*it).second;

  {
    long insnword = _ptrace_peekdata(child, va);
    BreakpointsInsnWord.at(Idx) = insnword;

    arch_put_breakpoint(&insnword);
    _ptrace_pokedata(child, va, insnword);
  }

  BreakpointPCMap[va] = Idx;
};

void _ptrace_get_cpu_state(pid_t child, cpu_state_t &out) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_GETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 0;
  unsigned long _data = reinterpret_cast<unsigned long>(&out.regs[0]);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGS failed : ") +
                             std::string(strerror(errno)));
#else
  struct iovec iov = {.iov_base = &out,
                      .iov_len = sizeof(cpu_state_t)};

  unsigned long _request = PTRACE_GETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGSET failed : ") +
                             std::string(strerror(errno)));
#endif
}

void _ptrace_set_cpu_state(pid_t child, const cpu_state_t &in) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_SETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&in.regs[0]);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_SETREGS failed : ") +
                             std::string(strerror(errno)));
#else
  struct iovec iov = {.iov_base = const_cast<cpu_state_t *>(&in),
                      .iov_len = sizeof(cpu_state_t)};

  unsigned long _request = PTRACE_SETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_SETREGSET failed : ") +
                             std::string(strerror(errno)));
#endif
}

unsigned long _ptrace_peekdata(pid_t child, uintptr_t addr) {
  unsigned long res;

  unsigned long _request = PTRACE_PEEKDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = reinterpret_cast<unsigned long>(&res);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_PEEKDATA failed : ") +
                             std::string(strerror(errno)));

  return res;
}

void _ptrace_pokedata(pid_t child, uintptr_t addr, unsigned long data) {
  unsigned long _request = PTRACE_POKEDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = data;

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_POKEDATA failed : ") +
                             std::string(strerror(errno)));
}

int ChildProc(void) {
  //
  // the request
  //
  ptrace(PTRACE_TRACEME);
  //
  // turns the calling thread into a tracee.  The thread continues to run
  // (doesn't enter ptrace-stop).  A common practice is to follow the
  // PTRACE_TRACEME with
  //
  raise(SIGSTOP);
  //
  // and allow the parent (which is our tracer now) to observe our
  // signal-delivery-stop.
  //

  std::vector<const char *> arg_vec;
  arg_vec.push_back(opts::Prog.c_str());

  for (const std::string &Arg : opts::Args)
    arg_vec.push_back(Arg.c_str());

  arg_vec.push_back(nullptr);

  std::vector<const char *> env_vec;
  for (char **env = ::environ; *env; ++env)
    env_vec.push_back(*env);

  //env_vec.push_back("LD_BIND_NOW=1");

  for (const std::string &Env : opts::Envs)
    env_vec.push_back(Env.c_str());

  env_vec.push_back(nullptr);

  execve(arg_vec[0],
         const_cast<char **>(&arg_vec[0]),
         const_cast<char **>(&env_vec[0]));

  /* if we got here, execve failed */
  int err = errno;
  cerr << "failed to execve (reason: " << strerror(err) << '\n';
  return 1;
}

void print_command(std::vector<const char *> &arg_vec) {
  for (const char *s : arg_vec) {
    if (!s)
      continue;

    cout << s << ' ';
  }

  cout << '\n';
}

std::string _ptrace_read_string(pid_t child, uintptr_t Addr) {
  std::string res;

  for (;;) {
    unsigned long word = _ptrace_peekdata(child, Addr);

    char ch = *reinterpret_cast<char *>(&word);

    if (ch == '\0')
      break;

    // one character at-a-time
    res.push_back(ch);
    ++Addr;
  }

  return res;
}

ssize_t _ptrace_memcpy(pid_t child, void *dest, const void *src, size_t n) {
  for (unsigned i = 0; i < n; ++i) {
    unsigned long word =
        _ptrace_peekdata(child, reinterpret_cast<uintptr_t>(src) + i);

    ((uint8_t *)dest)[i] = *((uint8_t *)&word);
  }

  return n;
}

void arch_put_breakpoint(void *code) {
#if defined(__x86_64__) || defined(__i386__)
  reinterpret_cast<uint8_t *>(code)[0] = 0xcc; /* int3 */
#elif defined(__aarch64__)
  reinterpret_cast<uint32_t *>(code)[0] = 0xd4200000; /* brk */
#elif defined(__arm__)
  reinterpret_cast<uint32_t *>(code)[0] = 0xe7ffdeff; /* triggers SIGILL */
#elif defined(__mips64) || defined(__mips__)
  reinterpret_cast<uint32_t *>(code)[0] = 0x0000000d; /* break */
#else
#error
#endif
}

} // namespace ptracetricks
