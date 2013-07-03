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

def str_to_bool(str):
    str = str.lower().strip()
    return str.startswith('y') or str.startswith('t') or str.startswith('1')

# Top-level build configuration
program = 'wired-leaf-is-a-codename' # come up with something better
src_dir = '#src/'     # Main daemon sources.
proto_dir = '#proto/' # Don't change this; we #include "proto/foo.pb-c.h".
lib_dir = '#lib/'     # Utility library (code shared between src/ and test/)
test_dir = '#test/'
test_include_dir ='#test/include'
build_dir = '#build/' # Scons requires this to live in the source tree :(.
build_src_dir = toplevel_join(build_dir, src_dir)
build_lib_dir = toplevel_join(build_dir, lib_dir)
build_test_dir = toplevel_join(build_dir, test_dir)
build_pyproto_dir = toplevel_join(build_dir, 'pyproto')
lib_deps = [
     # External dependencies:
     'event', 'event_pthreads', 'hdf5', 'protobuf', 'protobuf-c',
     # Extra system dependencies:
    'm', 'rt']
test_lib_deps = ['check'] # External dependencies for tests
verbosity_level = int(ARGUMENTS.get('V', 0))
skip_test_build = str_to_bool(ARGUMENTS.get('SKIP_TESTS', 'n'))
build_cc = ARGUMENTS.get('CC', 'gcc')
build_ld = ARGUMENTS.get('LD', 'gcc')
build_cflags_extra = ARGUMENTS.get('EXTRA_CFLAGS', '')
build_ldflags_extra = ARGUMENTS.get('EXTRA_LDFLAGS', '')

# Put all generated files underneath the build directory. protoc-c is
# configured to do this as well, to prevent anyone from carelessly
# committing generated protobuf sources.
VariantDir(build_lib_dir, lib_dir, duplicate=0)
VariantDir(build_src_dir, src_dir, duplicate=0)
VariantDir(build_test_dir, test_dir, duplicate=0)

# Build environment. Note we don't copy os.environ here.
env = Environment(CC=build_cc,
                  CCFLAGS=(('-pthread -std=c99 '
                            '-g -Wall -Wextra -Wpointer-arith -Werror ') +
                           build_cflags_extra),
                  CPPDEFINES={'_GNU_SOURCE': 1}, # we need Linux extensions
                  LINK=build_ld,
                  LINKFLAGS=build_ldflags_extra,
                  LIBS=lib_deps,
                  tools=['default', 'protocc'],
                  )
# Quiet build output unless user specifies verbose mode.
if verbosity_level == 0:
    env['ARCOMSTR'] = '\t[AR] $TARGET'
    env['CCCOMSTR'] = '\t[CC] $SOURCE'
    env['PROTOCCCOMSTR'] = '\t[PROTOC-C] $SOURCE'
    env['PROTOCCOMSTR'] = '\t[PROTOC] $SOURCE'
    env['RANLIBCOMSTR'] = '\t[RANLIB] $TARGET'
    env['LINKCOMSTR'] = '\t[LD] $TARGET'

# Protobuf code generation; see site_scons/site_tools/protocc.py.
proto_c_sources = []
protoccs = [env.ProtocC([], proto,
                        PROTOCCOUTDIR=env.GetBuildPath(build_lib_dir))
            for proto in Glob(proto_dir + '*.proto')]
protopys = [env.Protoc([], proto,
                       PROTOCOUTDIR=env.GetBuildPath(build_pyproto_dir))
            for proto in Glob(proto_dir + '*.proto')]
def c_nodes(nodes):
    return [n for n in nodes if str(n).endswith('c')]
for nodes in protoccs:
    proto_c_sources.extend(c_nodes(nodes))

# Mash together all the sources. These Glob() calls work automagically
# with the above VariantDir() calls.
lib_sources = Glob(os.path.join(build_lib_dir, '*.c'))
src_sources = Glob(os.path.join(build_src_dir, '*.c'))
test_sources_dict = {}
if not skip_test_build:
    for node in Glob(os.path.join(build_test_dir, '*')):
        test_name = str(node).rsplit(os.sep, 1)[1]
        test_sources_dict[test_name] = Glob(os.path.join(str(node), '*.c'))

# Utility library
libutil = env.Library(os.path.join(env.GetBuildPath(build_lib_dir),
                                   'daemonutil'),
                      lib_sources + proto_c_sources,
                      CPPPATH=[build_lib_dir])

# This is the final executable.
out_program = os.path.join(env.GetBuildPath(build_dir), program)
main = env.Program(out_program, src_sources + libutil,
                   CPPPATH=[build_lib_dir, src_dir])

# Test programs, one per subdirectory of test_dir.
for test_name, sources in test_sources_dict.iteritems():
    if test_name == 'include':
        continue
    test_out_dir = os.path.join(env.GetBuildPath(build_test_dir), test_name)
    test_prog = os.path.join(build_dir, test_name)
    test_defines = env['CPPDEFINES'].copy()
    test_defines.update({'TEST_DAEMON_PATH': str(out_program)})
    env.Program(test_prog, sources + libutil,
                CPPPATH=[build_lib_dir, test_out_dir, test_include_dir],
                CPPDEFINES=test_defines,
                LIBS=lib_deps + test_lib_deps)
