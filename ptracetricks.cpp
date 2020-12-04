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
          "currently the only option is --syscalls (-s)\n";
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
  while ((optc = getopt_long(_argc, _argv, "shvVp:", longopts, NULL)) != -1) {
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
typedef struct pt_regs user_regs_struct;
#endif

static void _ptrace_get_gpr(pid_t, user_regs_struct &out);
static void _ptrace_set_gpr(pid_t, const user_regs_struct &in);

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
static bool virtual_memory_mappings_for_process(
    pid_t child, std::unordered_map<std::string, uintptr_t> &out);

static void on_breakpoint(unsigned Idx, pid_t, const user_regs_struct &regs);

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
          if (virtual_memory_mappings_for_process(child, vmm)) {
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

          user_regs_struct gpr;
          _ptrace_get_gpr(child, gpr);

          long pc =
#if defined(__x86_64__)
              gpr.rip
#elif defined(__i386__)
              gpr.eip
#elif defined(__aarch64__)
              gpr.pc
#elif defined(__arm__)
              gpr.uregs[15]
#elif defined(__mips64) || defined(__mips__)
              gpr.cp0_epc
#else
#error
#endif
              ;

          //
          // determine whether this syscall is entering or has exited
          //
#if defined(__arm__)
          unsigned dir = gpr.uregs[12]; /* unambiguous */
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
            long no = gpr.orig_rax;

            long a1 = gpr.rdi;
            long a2 = gpr.rsi;
            long a3 = gpr.rdx;
            long a4 = gpr.r10;
            long a5 = gpr.r8;
            long a6 = gpr.r9;
#elif defined(__i386__)
            long no = gpr.orig_eax;

            long a1 = gpr.ebx;
            long a2 = gpr.ecx;
            long a3 = gpr.edx;
            long a4 = gpr.esi;
            long a5 = gpr.edi;
            long a6 = gpr.ebp;
#elif defined(__aarch64__)
            long no = gpr.regs[8];

            long a1 = gpr.regs[0];
            long a2 = gpr.regs[1];
            long a3 = gpr.regs[2];
            long a4 = gpr.regs[3];
            long a5 = gpr.regs[4];
            long a6 = gpr.regs[5];
#elif defined(__arm__)
            long no = gpr.uregs[7];

            long a1 = gpr.uregs[0];
            long a2 = gpr.uregs[1];
            long a3 = gpr.uregs[2];
            long a4 = gpr.uregs[3];
            long a5 = gpr.uregs[4];
            long a6 = gpr.uregs[5];
#elif defined(__mips64)
            long no = gpr.regs[2];

            long a1 = gpr.regs[4];
            long a2 = gpr.regs[5];
            long a3 = gpr.regs[6];
            long a4 = gpr.regs[7];
            long a5 = gpr.regs[8];
            long a6 = gpr.regs[9];
#elif defined(__mips__)
            long no = gpr.regs[2];

            long a1 = gpr.regs[4];
            long a2 = gpr.regs[5];
            long a3 = gpr.regs[6];
            long a4 = gpr.regs[7];
            long a5 = _ptrace_peekdata(child, gpr.regs[29 /* sp */] + 16);
            long a6 = _ptrace_peekdata(child, gpr.regs[29 /* sp */] + 20);
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
                gpr.rax
#elif defined(__i386__)
                gpr.eax
#elif defined(__aarch64__)
                gpr.regs[0]
#elif defined(__arm__)
                gpr.uregs[0]
#elif defined(__mips64) || defined(__mips__)
                gpr.regs[2]
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
            // we hit a breakpoint?
            //
            user_regs_struct gpr;
            _ptrace_get_gpr(child, gpr);

            long pc =
#if defined(__x86_64__)
                gpr.rip
#elif defined(__i386__)
                gpr.eip
#elif defined(__aarch64__)
                gpr.pc
#elif defined(__arm__)
                gpr.uregs[15]
#elif defined(__mips64) || defined(__mips__)
                gpr.cp0_epc
#else
#error
#endif
                ;

            auto it = BreakpointPCMap.find(pc);
            if (it == BreakpointPCMap.end()) {
              std::cerr << "warning: unknown breakpoint @ " << std::hex << pc
                        << std::endl;
            } else {
              unsigned Idx = (*it).second;

              if (opts::Verbose)
                std::cerr << "on_breakpoint @ " << std::hex << pc << std::endl;

              on_breakpoint(Idx, child, gpr);

              //
              // restore instruction word
              //
              long insnword = BreakpointsInsnWord.at(Idx);
              _ptrace_pokedata(child, pc, insnword);
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
          user_regs_struct gpr;
          _ptrace_get_gpr(child, gpr);

          long pc =
#if defined(__x86_64__)
              gpr.rip
#elif defined(__i386__)
              gpr.eip
#elif defined(__aarch64__)
              gpr.pc
#elif defined(__arm__)
              gpr.uregs[15]
#elif defined(__mips64) || defined(__mips__)
              gpr.cp0_epc
#else
#error
#endif
              ;

          if (stopsig == SIGILL &&
              BreakpointPCMap.count(pc)) {
            //
            // we hit a breakpoint
            //
            unsigned Idx = BreakpointPCMap[pc];

            if (opts::Verbose)
              std::cerr << "on_breakpoint @ " << std::hex << pc << std::endl;

            on_breakpoint(Idx, child, gpr);

            //
            // restore instruction word
            //
            long insnword = BreakpointsInsnWord.at(Idx);
            _ptrace_pokedata(child, pc, insnword);
          } else {
            //
            // (4) signal-delivery-stop
            //
            cerr << "delivering signal number " << stopsig << " [" << child << "]\n";

            // deliver it
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

static void print_register_state(std::ostream &out,
                                 const user_regs_struct &regs);

void on_breakpoint(unsigned Idx, pid_t, const user_regs_struct &regs) {
  print_register_state(std::cout, regs);
}

void print_register_state(std::ostream &out,
                          const user_regs_struct &regs) {
  auto &pc =
#if defined(__x86_64__)
      regs.rip
#elif defined(__i386__)
      regs.eip
#elif defined(__aarch64__)
      regs.pc
#elif defined(__arm__)
      regs.uregs[15]
#elif defined(__mips64) || defined(__mips__)
      regs.cp0_epc
#else
#error
#endif
      ;

  out << "IP 0x" << std::hex << pc << '\n';

#if defined(__arm__)
  out << std::hex << regs.uregs[0] << '\n';
  out << std::hex << regs.uregs[1] << '\n';
  out << std::hex << regs.uregs[2] << '\n';
  out << std::hex << regs.uregs[3] << '\n';
  out << std::hex << regs.uregs[4] << '\n';
  out << std::hex << regs.uregs[5] << '\n';
#endif
}

bool virtual_memory_mappings_for_process(pid_t child,
                                         std::unordered_map<std::string, uintptr_t> &out) {
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

void _ptrace_get_gpr(pid_t child, user_regs_struct &out) {
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
                      .iov_len = sizeof(user_regs_struct)};

  unsigned long _request = PTRACE_GETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGSET failed : ") +
                             std::string(strerror(errno)));
#endif
}

void _ptrace_set_gpr(pid_t child, const user_regs_struct &in) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_SETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&in.regs[0]);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_SETREGS failed : ") +
                             std::string(strerror(errno)));
#else
  struct iovec iov = {.iov_base = const_cast<user_regs_struct *>(&in),
                      .iov_len = sizeof(user_regs_struct)};

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
