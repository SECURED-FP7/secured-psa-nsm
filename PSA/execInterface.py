# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
#   File: execInterface.py
#   Created:    27/08/2014
#   Author:     BSC, VTT
#   Modified:   2016
#   Author:     VTT, jju, jk
#
#   Description:
#       Web service running on the PSA receiving the
#       configuration for the PSA from the PSC
#
#

import falcon
import requests
import logging
import json
import sys
import subprocess
import datetime

from BroManager import BroManager

# Bro instance:
bro = None

class execInterface():

    def __init__ ( self, home, configsPath, scriptsPath, psaLogLocation, psaID, pscAddr, psaAPIVersion ):
        self.psaHome      = home
        self.confsPath    = configsPath
        self.scripts_path = scriptsPath
        self.log_location = psaLogLocation
        self.psaID        = psaID
        self.pscAddr      = pscAddr
        self.psaAPI       = psaAPIVersion

    def on_post( self, request, response, command ):
        print "onPost"
        try:
            res = {}
            res[ "command" ] = command
            if command == "init":
                # receive the configuration, or init package
                script_file = self.confsPath + "/psaconf"
                fp=open(script_file, 'wb')
                while True:
                    chunk = request.stream.read(4096)
                    fp.write(chunk)
                    if not chunk:
                        break
                fp.close()

                # Make script executable for current user
                # hazardous.. we're root
                #st = os.stat(script_file)
                #os.chmod(script_file, st.st_mode | stat.S_IEXEC)

                # Run the init.sh and return it's return value
                res["ret_code"] = str(self.callInitScript())
                logging.info("PSA "+self.psaID+" configuration registered")
            elif command == "start":
                res["ret_code"] = str(self.callStartScript())
            elif command == "stop":
                res["ret_code"] = str(self.callStopScript())
            else:
                logging.info("POST: unknown command: " + command)
                response.status = falcon.HTTP_404
                return

            response.body = json.dumps(res)
            response.status = falcon.HTTP_200
            response.set_header("Content-Type", "application/json")

        except Exception as e:
            logging.exception( sys.exc_info()[0] )
            response.status = falcon.HTTP_501

    def on_get(self, request, response, command):
        try:
            res = {}
            res["command"] = command
            if command == "status":
                res["ret_code"] = self.callStatusScript().replace("\n", "")
            elif command == "configuration":
                res["ret_code"] = self.callGetConfigurationScript()
            elif command == "internet":
                res["ret_code"] = self.callGetInternetScript()
            elif command == "log":
                # Return PSA log or 501
                log = self.callGetLogScript()
                if log != None:
                    response.body = log
                    response.status = falcon.HTTP_200
                    response.set_header("Content-Type", "text/plain; charset=UTF-8")
                else:
                    response.status = falcon.HTTP_501
                return
            elif command == 'brolog':
                log = self.callGetBroLogScript()
                if log != None:
                    response.body = log
                    response.status = falcon.HTTP_200
                    response.set_header("Content-Type", "text/plain; charset=UTF-8")
                else:
                    response.status = falcon.HTTP_501
                return
            else:
                logging.info("GET: unknown command: " + command)
                response.status = falcon.HTTP_404
                return

            response.body = json.dumps(res)
            response.status = falcon.HTTP_200
            response.set_header("Content-Type", "application/json")
        except Exception as e:
            logging.exception(sys.exc_info()[0])
            response.status = falcon.HTTP_501

    def callInitScript( self ):
        global bro
        logging.info ("callInitScript()" )

        if bro != None:
            bro.stopBro()
            del bro

        bro = BroManager( self.psaHome, self )
        bro.loadConfig( self.confsPath + "/psaconf" )

        #ret = subprocess.call([ self.scripts_path + 'init.sh'])
        #return ret

        logging.info( 'BroManager initialized: %r' % ( bro != None ) )

        return 0

    def callStartScript( self ):
        logging.info( "callStartScript()" )

        if bro == None:
            logging.critical( 'BroManager instance not found.' )
            self.callInitScript()

        try:
#            bro.start()
            try:
                bro.connect()
                logging.info( 'Bro is already running.' )
                return 0
            except IOError as e:
                logging.info( 'No running instances of Bro found.' )
                bro.startBro()
                logging.info( 'Bro is running.' )
                return 0
        except Exception as e:
            logging.critical( 'Fatal error while connecting to Bro' )
            logging.critical( e  )

#        ret = subprocess.call([ self.scripts_path + 'start.sh'])
#        return ret
        return 1

    def callStopScript( self ):
        logging.info( "callStopScript()" )

        if bro != None:
            bro.stopBro()
            logging.info( 'Bro stopped.' )
        else:
            logging.info( 'Bro is not running.' )

#        ret = subprocess.call([ self.scripts_path + 'stop.sh'])
#        return ret

        return 0

    def callStatusScript( self ):
        proc = subprocess.Popen( [ self.scripts_path + 'status.sh' ],
                                 stdout = subprocess.PIPE,
                                 shell  = True )
        ( out, err ) = proc.communicate()
        return out

    def callGetConfigurationScript( self ):
        logging.info( "callGetConfigurationScript()" )
        proc = subprocess.Popen( [ self.scripts_path + 'current_config.sh' ],
                                 stdout = subprocess.PIPE,
                                 shell  = True )
        ( out, err ) = proc.communicate()
        return out

    def callGetInternetScript (self ):
        logging.info( "callGetInternetScript()" )
        proc = subprocess.Popen( [ self.scripts_path + 'ping.sh' ],
                                 stdout = subprocess.PIPE,
                                 shell  = True )
        ( out, err ) = proc.communicate()
        return out

    def callGetLogScript( self ):
        logging.info( "callGetLogScript()" )
        try:
            filename = self.confsPath + "/bro.log"
            #filename = self.log_location
            with open( filename, "r" ) as f:
                return f.read()
        except Exception as e:
            logging.exception( sys.exc_info()[0] )
            return None

    def get_client_address( self, environ ):
        try:
            return environ[ 'HTTP_X_FORWARDED_FOR' ].split( ',' )[ -1 ].strip()
        except KeyError:
            return environ[ 'REMOTE_ADDR' ]

    def callGetBroLogScript( self ):
        logging.info( "callGetBroLogScript()" )
        try:
            filename = self.confsPath + "/bro.log"
            with open( filename, "r") as f:
                return f.read()
        except Exception as e:
            logging.exception( sys.exc_info()[ 0 ] )
            return None

    def onEvent( self, logEntry ):
        filename = self.confsPath + "/bro.log"
        line = str( datetime.datetime.utcnow() ) + ': ' + logEntry
        with open( filename, "a" ) as logFile:
            logFile.write( line )

    def onNotifyEvent( self, policy, title, info):
        self.sendPsaEvent(policy, title, info)

    def sendPsaEvent(self, policy, title, info):
        logging.info( "sendPsaEvent()" )
        header = {"Content-Type": "application/json"}
        ev = {"psa_id": self.psaID, "event_title": title, "event_body": info, "extra_info": policy, "hspl_id": "", "mspl_id": ""}
        url = self.pscAddr + "/" + self.psaAPI + "/psaEvent/" + self.psaID

        try:
            requests.post(url, data=json.dumps(ev), headers=header)
        except Exception as e:
            logging.exception( sys.exc_info()[ 0 ] )

