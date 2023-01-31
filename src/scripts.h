#pragma once

static const char *compile_lib_script = R"ADFAAF(
import zipfile
import os
import blue
import marshal
import time
import py_compile

import tempfile
import os.path

def CreateZipFile(zipFilePath, inputFiles):
    msgString = 'gross creating zipfile %s' % zipFilePath
    print msgString
    with tempfile.TemporaryFile() as tmp:
        print "We have temp file " + str(tmp.name)
        with CleanPyZipFile(tmp, 'w') as tmpzip:
            print "We have PyZip cleaner"
            for pair in inputFiles:
                msgString = "Adding '%s' to zipfile " % pair[0]
                print msgString
                #inputPathOS = blue.rot.PathToFilename(pair[0]).rstrip('/')
                inputPathOS = pair[0]

                if not os.path.exists(inputPathOS):
                    print "'%s' doesn't exist!" % inputPathOS
                print "Writing "+pair[0]
                tmpzip.writepy(pair[0])

        tmpzip.close()
        with zipfile.PyZipFile(tmp, 'r') as tmpzip:
            infos = tmpzip.infolist()
            print "Have PyZipFile"
            print infos
            #zipFilePathOS = blue.rot.PathToFilename(zipFilePath)
            zipFilePathOS = zipFilePath
            zf = file(zipFilePathOS, 'wb')
            with zipfile.ZipFile(zf, 'w') as pyzip:
                for i in infos:
                    data = tmpzip.read(i.filename)
                    if i.filename.endswith('.pyc') or i.filename.endswith('.pyo'):
                        i.filename = i.filename[:-1] + 'j'
                        data = blue.JumbleString(data, True)
                    pyzip.writestr(i, data)


class CleanPyZipFile(zipfile.PyZipFile):

    def __init__(self, *args, **kwds):
        zipfile.PyZipFile.__init__(self, *args, **kwds)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        self.tmpfilename = tmp.name

    def close(self):
        zipfile.PyZipFile.close(self)
        tmp, self.tmpfilename = self.tmpfilename, None
        if tmp and os.path.isfile(tmp):
            os.unlink(tmp)
        return

    def _get_codename(self, pathname, basename):
        archivename = os.path.split(pathname + ('.pyc' if __debug__ else '.pyo'))[1]
        if basename:
            archivename = '%s/%s' % (basename, archivename)
        py_compile.compile(pathname + '.py', self.tmpfilename, None, True)
        return (
            self.tmpfilename, archivename)

def PackCode(path, out):
    zipName = out
    zipInput = ((path, None),)
    print "out: " + zipName
    print "in: " + path
    CreateZipFile(zipName, zipInput)

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
