#pragma once

static const char *uncompile_code_script = R"ADFAAF(
import blue
import zipfile
import zlib
import os
import marshal

import uncompyle2
import shutil
import cPickle

def unpack(name):
    print "Unpacking " + name
    f = open(name, "rb")
    magic, all, signature = cPickle.load(f)
    codes = cPickle.loads(all)['code']
    for (filename, type), (encrypted_code, hash) in codes:
        data = blue.UnjumbleString(encrypted_code, True)
        code = marshal.loads(data)
        filename = code.co_filename[48:]
        print filename + " : " + type + " | " + str(hash)
        out_filename = "tmp_out/" + os.path.splitext(filename)[0] + ".py"
        try:
            os.makedirs(os.path.dirname(out_filename))
        except:
            pass
        ff = open(out_filename, "wb")
        try:
            uncompyle2.uncompyle('2.7', code, ff)
        except Exception as e:
            print "Failed to decompile file "
            print e
            ff.close()
            os.remove(out_filename)
        #ff.write(data)
        ff.close()
    print signature.encode("hex")
    f.close()

unpack(input_path)
try:
    os.remove(output_path)
except:
    pass
shutil.move("tmp_out", output_path)

)ADFAAF";
static const char *compile_lib_script = R"ADFAAF(
import zipfile
import os
import blue
import marshal
import time
import py_compile

import tempfile
import os.path

def PackCode(path, out):
     with zipfile.ZipFile(out, "w") as zf:
        for root, dirs, files in os.walk(path):
            for file in files:
                filename = os.path.join(root, file)
                if os.path.splitext(filename)[1] != ".py":
                    print "Skipping " + filename
                    continue
                newfilename = os.path.splitext(filename)[0] + ".pyj"
                newfilename = newfilename.split(path)[1][1:]
                print newfilename
                f = open(filename, "r")
                #data = f.read()
                code2 = compile(f.read(), filename.encode("utf-8"), "exec")
                #data = blue.crypto.JumbleString(f.read(), True)
                base_data = marshal.dumps(code2)
                data = blue.JumbleString(base_data, True)
                test = blue.UnjumbleString(data, True)
                if test != base_data:
                    raise Exception("Data mismatch")
                zf.writestr(newfilename.encode('cp1252'), data)
                f.close()

PackCode(input_path, output_path)
)ADFAAF";

static const char *compile_code_script = R"ADFAAF(
print input_paths
print output_path

import cPickle
import sys
import imp
import blue
import marshal
import os
import binascii
import struct

def ScriptName(path):
	s = path.split("\\script")[1].replace('\\', '/')
	return s

def CarbonName(path):
	#s = path.split("")[1].replace('\\', '/')
	#return s
	s = path.split("carbon")[1].replace('\\', '/')
	return "carbon" + s

def FindCodeFiles(root, files, isCarbon, base):
	d = []
	for v in files:
		filename = os.path.join(root, v)
		if os.path.splitext(filename)[1] != ".py":
			continue
		f = open(filename, "r")
		source = f.read()
		f.close()

		name = ""
		if "carbon" in filename:
			name = CarbonName(filename)
		else:
			name = ScriptName(filename)

		print "> Compiling " + filename + " as script:/" + name
		code = compile(source, filename.encode("utf8"), 'exec')

		try:
			d.append(
				(("script:/" + name, "compiled"), (blue.JumbleString(marshal.dumps(code), True), hash(code)))
			)
		except Exception as e:
			print e
			#import traceback
			#traceback.print_exc()
	return d

def Generate(base, output):
	#print "Generating code from " + base
	all = {}
	all['code'] = []

	for path in base:
		print "Checking " + path
		for root, dirs, files in os.walk(path):
			all['code'] = all['code'] + FindCodeFiles(root, files, False, path)

	#TODO Rewrite this shit
	#print "Checking " + base + "/eve/client/script"
	#for root, dirs, files in os.walk(base + "/eve/client/script"):
	#	all['code'] = FindCodeFiles(root, files, False, base)

	#print "Checking " + base + "/eve/common/script"
	#for root, dirs, files in os.walk(base + "/eve/common/script/"):
	#	all['code'] = all['code'] + FindCodeFiles(root, files, False, base)

	#print "Checking " + base + "/carbon/"
	#for root, dirs, files in os.walk(base + "/carbon/"):
	#	all['code'] = all['code'] + FindCodeFiles(root, files, True, base)
	
	#print "Checking " + base + "/eve/client/alasiya" 
	#for root, dirs, files in os.walk(base + "/eve/alasiya/script/"):
	#	all['code'] = all['code'] + FindCodeFiles(root, files, False, base)

	#print "Checking " + base + "/eve/qatools/script"
	#for root, dirs, files in os.walk(base + "/eve/qatools/script/"):
	#	all['code'] = all['code'] + FindCodeFiles(root, files, False, base)

	#print "Checking " + base + "/eve/devtools/script"
	#for root, dirs, files in os.walk(base + "/eve/devtools/script/"):
	#	all['code'] = all['code'] + FindCodeFiles(root, files, False, base)

	all['cargo'] = {}
	all['preprocessed'] = False
	all['timestamp'] = "shit"

	print "Generating signature"
	allout = cPickle.dumps(all, -1)
	try:
		signature = blue.SignData(allout)
	except IOError as e:
		print e
		print "You probably don't have GoldenCD.pikl ;)"
	print "Signature: " + binascii.b2a_hex(signature)
	
	
	dataout = (168686339, allout, signature)
	d = cPickle.dumps(dataout)
	print "Writing " + output + " to ./" + output
	f = open(os.path.join(output_path), "wb")
	f.write(d)
	f.close()

try:
	Generate(input_paths, output_path)
except Exception as e:
	print e

)ADFAAF";
