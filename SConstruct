import os.path

Help("""
Build arguments:
\tV=1: verbose build output (quiet if not given or if V=0)
""")

def toplevel_join(base, child):
    return os.path.join(base, child.lstrip('#'))

# Top-level build configuration
program = 'wired-leaf-is-a-codename' # come up with something better
src_dir = '#src/'     # Main daemon sources.
proto_dir = '#proto/' # Don't change this; we #include "proto/foo.pb-c.h".
lib_dir = '#lib/'     # Utility library (code shared between src/ and test/)
build_dir = '#build/' # Scons requires this to live in the source tree :(.
build_src_dir = toplevel_join(build_dir, src_dir)
build_lib_dir = toplevel_join(build_dir, lib_dir)
lib_deps = ['hdf5', 'protobuf', 'protobuf-c', 'm'] # External dependencies
verbosity_level = int(ARGUMENTS.get('V', 0))

# Copy (link if possible) everything underneath the build directory,
# to e.g. prevent anyone from carelessly committing generated protobuf
# sources.
#
# I really tried to have output written to build/ without copying
# sources into it, but couldn't figure out how to get SCons to play
# nice.
VariantDir(build_lib_dir, lib_dir)
VariantDir(build_src_dir, src_dir)

# Build environment. Note we don't copy os.environ here.
env = Environment(CCFLAGS='-g -std=c99 -Wall -Wextra -Werror',
                  CPPDEFINES={'_XOPEN_SOURCE': 500},
                  LIBS=lib_deps,
                  tools=['default', 'protocc'],
                  )
# Quiet build output unless user specifies verbose mode.
if verbosity_level == 0:
    env['ARCOMSTR'] = '\t[AR] $TARGET'
    env['CCCOMSTR'] = '\t[CC] $SOURCE'
    env['PROTOCCCOMSTR'] = '\t[PROTOCC] $SOURCE'
    env['RANLIBCOMSTR'] = '\t[RANLIB] $TARGET'
    env['LINKCOMSTR'] = '\t[LD] $TARGET' # note the asymmetry

# Protobuf code generation.
# See site_scons/site_tools/protocc.py for details on ProtocC.
proto_c_sources = []
protos = [env.ProtocC([], proto, PROTOCCOUTDIR=env.GetBuildPath(build_lib_dir))
          for proto in Glob(proto_dir + '*.proto')]
def c_nodes(nodes):
    return [n for n in nodes if str(n).endswith('c')]
for nodes in protos:
    proto_c_sources.extend(c_nodes(nodes))

# Mash together all the sources.
lib_sources = Glob(os.path.join(build_lib_dir, '*.c'))
src_sources = Glob(os.path.join(build_src_dir, '*.c'))

# Utility library
libutil = env.Library(os.path.join(env.GetBuildPath(build_lib_dir),
                                   'daemonutil'),
                      lib_sources + proto_c_sources,
                      CPPPATH=[build_lib_dir])

# This is the final executable.
out_program = os.path.join(env.GetBuildPath(build_dir), program)
main = env.Program(out_program, src_sources + libutil,
                   CPPPATH=[build_lib_dir, build_src_dir])
