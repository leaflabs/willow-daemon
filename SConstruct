import os
import os.path

Help("""
Build arguments:
\tCC=<compiler>: set C compiler (default: gcc)
\tLD=<linker>: set linker (default: gcc)
\tEXTRA_CFLAGS="flag...": extra C compiler flags (default: none)
\tEXTRA_LDFLAGS="flag...": extra linker flags (default: none)
\tV=1: verbose build output (default: V=0, quiet output)
\tSKIP_TESTS=[y/n]: don't build tests (default: SKIP_TESTS=n, build tests)
""")

def toplevel_join(base, child):
    return os.path.join(base, child.lstrip('#'))

def node_basename(node):
    return str(node).rsplit(os.sep, 1)[1]

def str_to_bool(str):
    str = str.lower().strip()
    return str.startswith('y') or str.startswith('t') or str.startswith('1')

# Top-level build configuration
program = 'leafysd'   # The name of the daemon program.
src_dir = '#src/'     # Main daemon sources.
proto_dir = '#proto/' # Don't change this; we #include "proto/foo.pb-c.h".
lib_dir = '#lib/'     # Utility library (shared w/ src, test, libsng)
libsng_dir = '#libsng/' # Shared library used by SNG to interact w/ daemon.
test_dir = '#test/'
test_include_dir ='#test/include'
util_dir = '#util/'
build_dir = '#build/' # Scons requires this to live in the source tree :(.
build_src_dir = toplevel_join(build_dir, src_dir)
build_lib_dir = toplevel_join(build_dir, lib_dir)
# build dir for libsng
build_libsng_dir = toplevel_join(build_lib_dir, libsng_dir)
# libsng files actually needed by the user (shared object and its headers):
build_libsng_install_dir = toplevel_join(build_dir, libsng_dir)
build_test_dir = toplevel_join(build_dir, test_dir)
build_util_dir = toplevel_join(build_dir, util_dir)
build_pyproto_dir = toplevel_join(build_dir, 'pyproto')
lib_deps = [
     # External dependencies:
     'event', 'event_pthreads', 'hdf5', 'protobuf-c']
libsng_deps = ['protobuf-c']
test_lib_deps = ['check_pic', 'sng'] # External dependencies for tests
verbosity_level = int(ARGUMENTS.get('V', 0))
skip_test_build = str_to_bool(ARGUMENTS.get('SKIP_TESTS', 'n'))
build_cc = ARGUMENTS.get('CC', 'gcc')
build_ld = ARGUMENTS.get('LD', 'gcc')
build_base_cflags = '-std=c99 -g -Wall -Wextra -Wpointer-arith -Werror'
build_libsng_cflags = build_base_cflags
build_cflags = '-pthread ' + build_base_cflags
build_cflags_extra = ARGUMENTS.get('EXTRA_CFLAGS', '')
build_ldflags_extra = ARGUMENTS.get('EXTRA_LDFLAGS', '')

# Put all generated files underneath the build directory. protoc-c is
# configured to do this as well, to prevent anyone from carelessly
# committing generated protobuf sources.
VariantDir(build_lib_dir, lib_dir, duplicate=0)
VariantDir(build_src_dir, src_dir, duplicate=0)
VariantDir(build_test_dir, test_dir, duplicate=0)
VariantDir(build_util_dir, util_dir, duplicate=0)

# Base build environment. Note we don't copy os.environ here.
env = Environment(CC=build_cc,
                  CCFLAGS=build_cflags + ' ' + build_cflags_extra,
                  CPPDEFINES={'_GNU_SOURCE': 1}, # we need Linux extensions
                  CPPPATH=[build_lib_dir, src_dir],
                  LINK=build_ld,
                  LINKFLAGS=build_ldflags_extra,
                  LIBS=lib_deps,
                  tools=['default', 'protocc'],
                  )
# Quiet build output unless user specifies verbose mode.
if verbosity_level == 0:
    env['ARCOMSTR'] = '[AR] $TARGET'
    env['CCCOMSTR'] = '[CC] $SOURCE'
    env['PROTOCCCOMSTR'] = '[PROTOC-C] $SOURCE'
    env['PROTOCCOMSTR'] = '[PROTOC] $SOURCE'
    env['RANLIBCOMSTR'] = '[RANLIB] $TARGET'
    env['LINKCOMSTR'] = '[LD] $TARGET'

# Protobuf code generation; see site_scons/site_tools/protocc.py.
proto_c_sources = []
proto_c_headers = []
protoccs = [env.ProtocC([], proto,
                        PROTOCCOUTDIR=env.GetBuildPath(build_lib_dir))
            for proto in Glob(proto_dir + '*.proto')]
protopys = [env.Protoc([], proto,
                       PROTOCOUTDIR=env.GetBuildPath(build_pyproto_dir))
            for proto in Glob(proto_dir + '*.proto')]
def ext_nodes(nodes, ext):
    return [n for n in nodes if str(n).endswith(ext)]
def c_nodes(nodes):
    return ext_nodes(nodes, 'c')
def h_nodes(nodes):
    return ext_nodes(nodes, 'h')
for nodes in protoccs:
    proto_c_sources.extend(c_nodes(nodes))
    proto_c_headers.extend(h_nodes(nodes))

# Mash together all the sources. These Glob() calls work automagically
# with the above VariantDir() calls.
lib_sources = Glob(os.path.join(build_lib_dir, '*.c'))
src_sources = Glob(os.path.join(build_src_dir, '*.c'))
util_sources_dict = {}
for node in Glob(os.path.join(build_util_dir, '*')):
    util_name = node_basename(node)
    if os.path.isdir(node.srcnode().path):
        util_sources = Glob(os.path.join(str(node), '*.c'))
        if util_sources:
            util_sources_dict[util_name] = util_sources
test_sources_dict = {}
if not skip_test_build:
    for node in Glob(os.path.join(build_test_dir, '*')):
        if os.path.isdir(node.srcnode().path):
            test_name = node_basename(node)
            if test_name == 'include':
                continue
            test_sources_dict[test_name] = Glob(os.path.join(str(node), '*.c'))

# Static support library
libutil = env.Library(os.path.join(env.GetBuildPath(build_lib_dir),
                                   'daemonutil'),
                      lib_sources + proto_c_sources)

# This is the final executable.
out_program = os.path.join(env.GetBuildPath(build_dir), program)
main = env.Program(out_program, src_sources + libutil)

# libsng
shenv = env.Clone(CCFLAGS=build_libsng_cflags,
                  LIBS=libsng_deps,
                  CPPPATH=[build_lib_dir])
if verbosity_level == 0:
    shenv['SHCCCOMSTR'] = '[SHCC] $SOURCE'
    shenv['SHLINKCOMSTR'] = '[SHLD] $TARGET'
    shenv['INSTALLSTR'] = '[LIBSNG] $TARGET'
shenv.VariantDir(build_libsng_dir, libsng_dir, duplicate=0)
libsng_sources = shenv.Glob(os.path.join(libsng_dir, '*.c'))
libsng_headers = shenv.Glob(os.path.join(libsng_dir, '*.h'))
libsng_target = os.path.join(env.GetBuildPath(build_libsng_dir), 'sng')
libsng_shobjs = shenv.SharedObject(target=libsng_target,
                                   source=libsng_sources)
libsng_obj = shenv.SharedLibrary(target=libsng_target,
                                 source=(libsng_shobjs + lib_sources +
                                         proto_c_sources),
                                 CPPPATH=[build_lib_dir])

# Install builders for libsng (i.e., just the shared object file and
# its relevant headers.)
foo = shenv.Install(build_libsng_install_dir, libsng_obj)
libsng_incls = toplevel_join(build_libsng_install_dir, 'include')
libsng_proto_incls = toplevel_join(libsng_incls, 'proto')
for h in proto_c_headers:
    shenv.Install(libsng_proto_incls, h)
for h in libsng_headers:
    shenv.Install(libsng_incls, h)

# Test programs, one per subdirectory of test_dir.
#
# (test_dir is also allowed to contain scripts, which we ignore).
test_defines = env['CPPDEFINES'].copy()
test_defines.update({'TEST_DAEMON_PATH': str(out_program)})
testenv = env.Clone(LIBS=test_lib_deps + lib_deps,
                    LIBPATH=[build_libsng_dir],
                    CPPDEFINES=test_defines)
for test_name, sources in test_sources_dict.iteritems():
    test_out_dir = os.path.join(env.GetBuildPath(build_test_dir), test_name)
    test_prog = os.path.join(build_dir, test_name)
    testenv.Program(test_prog, sources + libutil,
                    CPPPATH=[build_lib_dir, test_out_dir, test_include_dir,
                             build_libsng_dir])

# Utility programs (written in C), one per subdirectory of
# util_dir. (util_dir also contains scripts, which we ignore).
#
# These are built in the same environment as the daemon. This allows
# them access to the daemon's include files, which is arguably bad,
# but I don't care.
for util_name, sources in util_sources_dict.iteritems():
    util_prog = os.path.join(build_dir, util_name)
    env.Program(util_prog, sources + libutil)
