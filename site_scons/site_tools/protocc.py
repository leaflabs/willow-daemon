# Pattern-matched from a C++ and Python version available here:
# http://www.scons.org/wiki/ProtocBuilder

"""protocc.py: protoc/protoc-c Builder for SCons

This Builder invokes protoc-c to generate C from a .proto file, and
protoc to generate Python.
"""

__author__ = "Scott Stafford, Marti Bolivar"

import SCons.Action
import SCons.Builder
import SCons.Util

from SCons.Script import File, Dir

import os.path

######################################################################
# !!!!! IMPORTANT !!!!!
#
# The C interface uses a separate tool, protoc-c, which is a modified
# version of Google's tool, protoc. This means there are two sets of
# variables for controlling how ser/des code is generated from .proto
# files:
#
# Set 1: tools for C (with protoc-c)
#
#     PROTOCC: protoc-c binary (detected; e.g. "protoc-c", "/usr/bin/protoc-c")
#     PROTOCCCOM: protoc-c build command (note _THREE_ C's)
#     PROTOCCCOMSTR: protoc-c string to display during build (_THREE_ C's)
#     PROTOCCFLAGS: flags for protoc-c (_TWO_ C's)
#     PROTOCCOUTDIR: output directory (_TWO_ C's)
#
# Set 2: tools for Python (with protoc)
#
#     PROTOC: protoc binary (detected; e.g. "protoc", "/usr/bin/protoc")
#     PROTOCCOM: protoc command (only _TWO_ C's)
#     PROTOCCOMSTR: protoc string to display during build (_TWO_ C's)
#     PROTOCFLAGS: flags for protoc (_ONE_ C)
#     PROTOCOUTDIR: output directory (_ONE_ C)
#
# However, the following variables are shared:
#
# PROTOPATH: list of paths containing external .proto dependencies
# PROTOSRCSUFFIX: defaults to ".proto"
#
# See generate(), below, for defaults/details.
#
######################################################################

def with_corrected_paths(source):
    dirOfCallingSConscript = Dir('.').srcnode()
    ret = []
    for src in source:
        commonprefix = os.path.commonprefix([dirOfCallingSConscript.path,
                                             src.srcnode().path])
        if len(commonprefix) > 0:
            slice_start = len(commonprefix + os.sep)
        else:
            slice_start = 0
        ret.append(src.srcnode().path[slice_start:])
    return ret

### protoc-c (for C)

protocc = 'protoc-c' # for C
ProtocCAction = SCons.Action.Action('$PROTOCCCOM', '$PROTOCCCOMSTR') # C
def ProtocCEmitter(target, source, env): # C
    def handle_src(source):
        modulename = os.path.splitext(src)[0]
        if env['PROTOCCOUTDIR']:
            base = os.path.join(env['PROTOCCOUTDIR'] , modulename)
            target.extend([base + '.pb-c.c', base + '.pb-c.h'])
        else:
            print "PROTOCCOUTDIR unset; not building C for .proto"
    for src in with_corrected_paths(source):
        handle_src(src)
    return target, source
ProtocCBuilder = SCons.Builder.Builder(action=ProtocCAction,
                                       emitter=ProtocCEmitter,
                                       srcsuffix='$PROTOSRCSUFFIX')

### protoc (for Python)

protoc = 'protoc'
ProtocAction = SCons.Action.Action('$PROTOCCOM', '$PROTOCCOMSTR')
def ProtocEmitter(target, source, env):
    def handle_src(src):
        modulename = os.path.splitext(src)[0]
        if env['PROTOCOUTDIR']:
            base = os.path.join(env['PROTOCOUTDIR'] , modulename)
            target.extend([base + '_pb2.py'])
        else:
            print "PROTOCOUTDIR unset; not building Python for .proto"
    for src in with_corrected_paths(source):
        handle_src(src)
    return target, source
ProtocBuilder = SCons.Builder.Builder(action=ProtocAction,
                                      emitter=ProtocEmitter,
                                      srcsuffix='$PROTOSRCSUFFIX')

def generate(env):
    """Add Builders and construction variables for protoc-c and protoc to
    an Environment.
    """

    # Shared
    env['PROTOSRCSUFFIX']  = '.proto'
    env['PROTOPATH'] = SCons.Util.CLVar('')

    # protoc-c (C)
    env['PROTOCCOUTDIR'] = '${SOURCE.dir}'
    try:
        bld = env['BUILDERS']['ProtocC']
    except KeyError:
        env['BUILDERS']['ProtocC'] = ProtocCBuilder
    env['PROTOCC'] = env.Detect(protocc) or protocc
    env['PROTOCCFLAGS'] = SCons.Util.CLVar('')
    env['PROTOCCCOM'] = ('$PROTOCC ${["-I%s" % x for x in PROTOPATH]} '
                         '$PROTOCCFLAGS --c_out=$PROTOCCOUTDIR ${SOURCES}')

    # protoc (Python)
    # env['PROTOCOUTDIR'] = '${SOURCE.dir}'
    try:
        bld = env['BUILDERS']['Protoc']
    except KeyError:
        env['BUILDERS']['Protoc'] = ProtocBuilder
    env['PROTOC'] = env.Detect(protoc) or protoc
    env['PROTOCFLAGS'] = SCons.Util.CLVar('')
    env['PROTOCCOM'] = ('$PROTOC ${["-I%s" % x for x in PROTOPATH]} '
                        '$PROTOCFLAGS --python_out=$PROTOCOUTDIR ${SOURCES}')

def exists(env):
    return env.Detect(protocc) and env.Detect(protoc)
