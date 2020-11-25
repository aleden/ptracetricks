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
#include <unordered_map>

#include <llvm/Support/InitLLVM.h>
//#include <llvm/Support/WithColor.h>
#include <llvm/Support/CommandLine.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)   __builtin_expect(!!(x), 0)
#endif

namespace cl = llvm::cl;
namespace fs = std::filesystem;

//using llvm::WithColor;

using namespace std;

namespace opts {

static cl::OptionCategory PtraceTricksCategory("Specific Options");

static cl::opt<std::string> Prog(cl::Positional, cl::desc("prog"), cl::Optional,
                                 cl::value_desc("filename"),
                                 cl::cat(PtraceTricksCategory));

static cl::list<std::string> Args("args", cl::CommaSeparated,
                                  cl::value_desc("arg_1,arg_2,...,arg_n"),
                                  cl::desc("Program arguments"),
                                  cl::cat(PtraceTricksCategory));

static cl::opt<unsigned> PID("attach", cl::value_desc("pid"),
                             cl::desc("Attach to existing process"),
                             cl::cat(PtraceTricksCategory));

static cl::list<std::string>
    Envs("env", cl::CommaSeparated,
         cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
         cl::desc("Extra environment variables"),
         cl::cat(PtraceTricksCategory));

static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"),
            cl::cat(PtraceTricksCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for -verbose."),
                              cl::aliasopt(Verbose),
                              cl::cat(PtraceTricksCategory));

static cl::opt<bool> Syscalls("syscalls", cl::desc("Always trace system calls"),
                              cl::cat(PtraceTricksCategory));

static cl::alias SyscallsAlias("s", cl::desc("Alias for -syscalls."),
                               cl::aliasopt(Syscalls),
                               cl::cat(PtraceTricksCategory));

} // namespace opts

namespace ptracetricks {

static int ChildProc(void);
static int ParentProc(pid_t child);

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

  llvm::InitLLVM X(_argc, _argv);

  cl::HideUnrelatedOptions({&opts::PtraceTricksCategory /* , &llvm::ColorCategory */});
  cl::ParseCommandLineOptions(_argc, _argv, "stupid ptrace tricks\n");

  if (opts::PID) {
    //
    // mode 1: attach to existing process
    //
    cerr << "TODO!\n";
    return 1;
  } else {
    //
    // mode 2: execute the given process
    //
    if (!fs::exists(fs::path(opts::Prog.c_str()))) {
      cerr << "given program does not exist";
      return 1;
    }

    pid_t child = fork();
    if (!child)
      return ptracetricks::ChildProc();

    return ptracetricks::ParentProc(child);
  }
}

namespace ptracetricks {

static bool SeenExec = false;

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

static void IgnoreCtrlC(void);

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

int ParentProc(pid_t child) {
  IgnoreCtrlC();

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

  //
  // select ptrace options
  //
  int ptrace_options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                       PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

  //
  // set those options
  //
  cerr << "parent: setting ptrace options...\n";

  ptrace(PTRACE_SETOPTIONS, child, 0, ptrace_options);

  cerr << "ptrace options set!\n";

  siginfo_t si;
  long sig = 0;

  try {
    for (;;) {
      if (likely(!(child < 0))) {
        if (unlikely(ptrace(SeenExec && opts::Syscalls
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

          auto &pc =
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
            auto &no = gpr.orig_rax;

            auto &a1 = gpr.rdi;
            auto &a2 = gpr.rsi;
            auto &a3 = gpr.rdx;
            auto &a4 = gpr.r10;
            auto &a5 = gpr.r8;
            auto &a6 = gpr.r9;
#elif defined(__i386__)
            auto &no = gpr.orig_eax;

            auto &a1 = gpr.ebx;
            auto &a2 = gpr.ecx;
            auto &a3 = gpr.edx;
            auto &a4 = gpr.esi;
            auto &a5 = gpr.edi;
            auto &a6 = gpr.ebp;
#elif defined(__aarch64__)
            auto &no = gpr.regs[8];

            auto &a1 = gpr.regs[0];
            auto &a2 = gpr.regs[1];
            auto &a3 = gpr.regs[2];
            auto &a4 = gpr.regs[3];
            auto &a5 = gpr.regs[4];
            auto &a6 = gpr.regs[5];
#elif defined(__arm__)
            auto &no = gpr.uregs[7];

            auto &a1 = gpr.uregs[0];
            auto &a2 = gpr.uregs[1];
            auto &a3 = gpr.uregs[2];
            auto &a4 = gpr.uregs[3];
            auto &a5 = gpr.uregs[4];
            auto &a6 = gpr.uregs[5];
#elif defined(__mips64)
            auto &no = gpr.regs[2];

            auto &a1 = gpr.regs[4];
            auto &a2 = gpr.regs[5];
            auto &a3 = gpr.regs[6];
            auto &a4 = gpr.regs[7];
            auto &a5 = gpr.regs[8];
            auto &a6 = gpr.regs[9];
#elif defined(__mips__)
            auto &no = gpr.regs[2];

            auto &a1 = gpr.regs[4];
            auto &a2 = gpr.regs[5];
            auto &a3 = gpr.regs[6];
            auto &a4 = gpr.regs[7];
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

            auto &a1 = syscall_state.a1;
            auto &a2 = syscall_state.a2;
            auto &a3 = syscall_state.a3;
            auto &a4 = syscall_state.a4;
            auto &a5 = syscall_state.a5;
            auto &a6 = syscall_state.a6;
            auto &no = syscall_state.no;

            if (no >= 0 &&
                no < syscalls::NR_MAX &&
                syscall_names[no]) {
              const char *const nm = syscall_names[no];

              //
              // print syscall
              //
              cout << nm << '(';

              //
              // print arguments
              //
              try {
                switch (no) {
                case syscalls::NR::openat:
                  cout << dec << a1 << ", \"" << _ptrace_read_string(child, a2) << '\"';
                  break;
                case syscalls::NR::access:
                  cout << '\"' << _ptrace_read_string(child, a1) << "\", " << std::dec << a2;
                  break;
                case syscalls::NR::close:
                  cout << std::dec << a1;
                  break;
                case syscalls::NR::exit_group:
                  cout << std::dec << a1;
                  break;

                case syscalls::NR::read:
                case syscalls::NR::write:
                  cout << std::dec << a1 << ", 0x" << std::hex << a2 << ", " << std::dec << a3;
                  break;
                case syscalls::NR::brk:
                  cout << "0x" << std::hex << a1;
                  break;
                case syscalls::NR::mprotect:
                  cout << "0x" << std::hex << a1 << ", " << std::dec << a2 << ", " << a3;
                  break;
                case syscalls::NR::mmap2:
                  cout << "0x" << std::hex << a1 << ", " << std::dec << a2 << ", " << a3 << ", " << a4 << ", " << a5 << ", " << a6;
                  break;
                case syscalls::NR::munmap:
                  cout << "0x" << std::hex << a1 << ", " << std::dec << a2;
                  break;
                case syscalls::NR::prctl:
                  cout << std::dec
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

              cout << ") = ";

              if (IsRetPointer)
                cout << "0x" << std::hex << ret;
              else
                cout << std::dec << ret;

              cout << endl;
            }
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
            //on_breakpoint(child, tcg, dis);
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
          cerr << "delivering signal number " << stopsig << " [" << child << "]\n";

          // deliver it
          sig = stopsig;
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

void IgnoreCtrlC(void) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = SIG_IGN;

  if (sigaction(SIGINT, &sa, nullptr) < 0) {
    int err = errno;
    cerr << "sigaction failed (" << strerror(err) << ")\n";
  }
}

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
#elif defined(__mips64) || defined(__mips__)
  reinterpret_cast<uint32_t *>(code)[0] = 0x0000000d; /* break */
#else
// TODO XXX
//#error
#endif
}

} // namespace ptracetricks
