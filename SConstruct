import os.path

Help("""
Build arguments:
\tV=1: verbose build output (quiet if not given or if V=0)
""")

# Top-level build configuration
program = 'wired-leaf-is-a-codename' # come up with something better
src_dir = '#src/'
proto_dir = '#proto/' # Don't change this; we #include "proto/foo.pb-c.h".
build_dir = '#build/' # Scons requires this to live in the source tree :(.
lib_deps = ['hdf5', 'protobuf', 'protobuf-c', 'm']
verbosity_level = (int(ARGUMENTS.get('V'))
                   if ARGUMENTS.get('V') is not None
                   else 0)

def scons_path_fixup(dir):
    """Hack for converting SCons-style paths-with-leading-# to
    real paths."""
    if dir.startswith('#'):
        relpath = os.path.join(str(Dir('.').srcnode()), dir[1:])
        return relpath

# Copy (link if possible) everything to the build directory, to
# e.g. prevent anyone from carelessly committing generated protobuf
# sources.
#
# I really tried to have output written to build/ without copying
# sources into it, but couldn't figure out how to get SCons to play
# nice.
VariantDir(build_dir, src_dir, duplicate=1)

# Build environment. Note we don't copy os.environ here.
env = Environment(CCFLAGS='-g -std=c99 -Wall -Wextra -Werror',
                  CPPDEFINES={'_XOPEN_SOURCE': 500},
                  CPPPATH=[build_dir],
                  LIBS=lib_deps,
                  tools=['default', 'protocc'],
                  )
# Quiet build output unless user specifies verbose mode.
if verbosity_level == 0:
    env['CCCOMSTR'] = '\t[CC] $SOURCE'
    env['LINKCOMSTR'] = '\t[LD] $SOURCE'
    env['PROTOCCCOMSTR'] = '\t[PROTOCC] $SOURCE'

# This will hold the paths to any generated C files. For now, that's
# just protoc-c output.
generated_c_sources = []

# Protobuf code generation.
# See site_scons/site_tools/protocc.py for details on ProtocC.
protos = [env.ProtocC([], proto, PROTOCCOUTDIR=scons_path_fixup(build_dir))
          for proto in Glob(proto_dir + '*.proto')]
def c_nodes(nodes):
    return [n for n in nodes if str(n).endswith('c')]
for nodes in protos:
    generated_c_sources.extend(c_nodes(nodes))

# Mash together all the sources.
all_sources = Glob(os.path.join(build_dir, '*.c')) + generated_c_sources
# This is the final executable.
# XXX why the fuck doesn't VariantDir put it in build/ for me?
out_program = os.path.join(scons_path_fixup(build_dir), program)
main = env.Program(out_program, all_sources)
