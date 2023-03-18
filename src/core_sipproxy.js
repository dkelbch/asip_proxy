/*!
    SIP proxy used for connectivity service against other SIP phones, if needed
*/

var sip     = require('sip');
var proxy   = require('./lib_sipproxy.js');
var digest  = require('sip/digest');

const util    = require('util');
const os      = require('os');

const fs    = require('fs');

const     DSTR_COMP_CORE_SIPPROXY = '[core sip proxy] ';
const     D_SIPCLIENT_REGISTRATION_EXPIRE=180;

var     debug       = true; //false;
var     realm       = os.hostname();
var     statistic   ={
    startTs : 0,
    recvCnt : 0,
    sendCnt : 0, 
};

function    getCurTimestamp(){
    let d = new Date();
    return d.getTime();
  }
  function  getCurTime(){
    let d = new Date();
    return d.toUTCString();
  }

class registrar {
    constructor(config, debug = false){
        this._debug = debug;
        this._db    = config.accounts;
        if ( this._debug == true){
            console.log( DSTR_COMP_CORE_SIPPROXY + '[registrar] database loaded');
            //console.log( this._db);
        }

    }

    findEntry(user, expired_check=false){
        let _entry = this._db.find(el => {return el.user == user})
        // \todo clean-up entries, if expired and it is not re-registered, again. 
        //if ( (expired_check== true) && (_entry.lastTS + (D_SIPCLIENT_REGISTRATION_EXPIRE*1000) > ally_util.getCurTimestamp() ) ){
            // return undefined
        //    return;
        //}

        return _entry;
    }

    updateEntry(user,contact,state){
        for(let i=0; i < this._db.length; i++){
            if ( this._db[i].user == user){
                this._db[i].contact = contact;
                this._db[i].state   = state;
                this._db[i].lastTS  = getCurTimestamp();
                break;
            }
        }
    }

    updateSessionEntry(user,session){
        for(let i=0; i < this._db.length; i++){
            if ( this._db[i].user == user){
                this._db[i].session = session;
                break;
            }
        }
    }
}

var     sipregistrar = {};

function registrarLoad(config){
    sipregistrar = new registrar(config, true);
}

function registrarAccountFind(_user, expired_check=false){
    return sipregistrar.findEntry(_user,expired_check);
}

function registrarAccountUpdate(_user, _contact, _state){
    sipregistrar.updateEntry(_user, _contact, _state);
}
function registrarAccountSessionUpdate(_user, _session){
    sipregistrar.updateSessionEntry(_user, _session)
}

function registrarAccountAuthentication(_user, _user_record, rq){
    let ret = true;
    // localhost without authentication

    if(!digest.authenticateRequest(_user_record.session, rq, {user: _user, password: _user_record.pwd})) {
        sip.send(digest.challenge(_user_record.session, sip.makeResponse(rq, 401, 'Authentication Required')));
        
        registrarAccountSessionUpdate(_user, _user_record.session);
        ret = false;
    }

    return ret;
}

function registrarRegisterMethod(rq){
    let ret = false;

    if ( rq.method == 'REGISTER'){
        let user        = sip.parseUri(rq.headers.to.uri).user;
        let user_record = registrarAccountFind(user);
        let rsp         = sip.makeResponse(rq, 404, 'not found');
        
        if ( user_record != undefined){
            // record is available, let's check if re-register
            if (debug==true){console.log(DSTR_COMP_CORE_SIPPROXY + 'register ' + rq.headers.to.uri);}
            
            user_record.session = user_record.session || {realm:realm};
            if (!registrarAccountAuthentication(user,user_record,rq) ){

            //    if(!digest.authenticateRequest(user_record.session, rq, {user: user, password: user_record.pwd})) {
            //       proxy.send(digest.challenge(user_record.session, sip.makeResponse(rq, 401, 'Authentication Required')));
                    
            //     registrarAccountSessionUpdate(user, user_record.session);
            //    return true;
            }
            else {
                if ( rq.headers.expires == 0){
                    registrarAccountSessionUpdate(user, null);

                    registrarAccountUpdate(user, null,'none');

                    rsp.status          = 200;
                    rsp.reason          = 'OK';
                }
                else{
                    registrarAccountSessionUpdate(user, user_record.session);
                    
                    registrarAccountUpdate(user, rq.headers.contact,'registered');
                    rsp.status          = 200;
                    rsp.reason          = 'OK';
                    rsp.headers.to.tag  = Math.floor(Math.random() * 1e6);
                    rsp.headers.expires = D_SIPCLIENT_REGISTRATION_EXPIRE;
                    rsp.headers.contact = rq.headers.contact;
                }
            }
        }
        else{
            // user is not available, may put source IP to firewall handling
            console.error(DSTR_COMP_CORE_SIPPROXY + 'record of ' + rq.headers.to.uri + ' is not found');
        }

        proxy.send(rsp);
        ret = true;
    }

    return ret;
}

function sipproxylogTraffic(m,direct){
    //console.log('recv:' + util.inspect(m, null, null));
    if ( debug == true ){
        if( m.method != undefined){
        
            console.log( DSTR_COMP_CORE_SIPPROXY + direct 
                         + 'method: ' + m.method 
                         + ' uri: ' + m.uri 
                      + ' from: ' + m.headers.from.uri
                      + ' to : ' + m.headers.to.uri);
        }
        else{
            console.log( DSTR_COMP_CORE_SIPPROXY + direct + 'status: ' + m.status 
                      + ' from: ' + m.headers.from.uri
                      + ' to : ' + m.headers.to.uri);
        }
    }
}

function sipproxyStart(config){
    registrarLoad(config);
    
    proxy.start({
        logger: {
            recv: function(m){statistic.recvCnt++;;sipproxylogTraffic(m,'IN ')},
            send: function(m){statistic.sendCnt++;;sipproxylogTraffic(m,'OUT ')}, 
            error: function(e) { console.error(e.stack); }
        }
      }, function(rq) {
        if ( registrarRegisterMethod(rq) == false){
            // proxy activities, may need later to grep also publish method, in order to handle present indication
            let user = sip.parseUri(rq.uri).user;
            let user_record = registrarAccountFind(user, true);
    
            if ( rq.method == 'INVITE'){
                console.info("INVITE from " + rq.headers.from.uri + " to " + rq.headers.to.uri );
            }

            if (rq.method == 'cancel'){
                console.error('Cancel');
            }
            if ( rq.method == 'PUBLISH'){
                rq.uri = user_record.contact[0].uri;
                proxy.send(sip.makeResponse(rq, 405, 'Method not allowed'));
            }
            else if ( (user_record != undefined) && (user_record.contact.length > 0) ){
                // reply with trying and forward request to destination
                rq.uri = user_record.contact[0].uri;
                proxy.send(sip.makeResponse(rq, 100, 'Trying'));
    
                proxy.send(rq);
            }
            else{
                // 
                proxy.send(sip.makeResponse(rq, 404, 'Not Found'));
            }
       }
    });
}

function  comSipBrokerStart(config){
    return new Promise((resolve,reject)=>{
        debug = true;

        statistic.startTs = getCurTimestamp();
        statistic.recvCnt = 0;
        statistic.sendCnt = 0;
                        
        sipproxyStart(config);

        resolve();
    });
}

function  comSipBrokerStop(){
    console.log( "to be implemented");
}

function  comSipBrokerStatus(){
    console.log( statistic );
    return statistic;
}

module.exports ={
    start   : comSipBrokerStart,
    stop    : comSipBrokerStop,
    status  : comSipBrokerStatus,
  };
 
var database ={
    accounts : [
        {user : "1000", pwd :"p1000", contact :"",  state :"none", expire:0},
        {user : "1001", pwd :"p1001", contact :"",  state :"none", expire:0},
        {user : "1002", pwd :"p1002", contact :"",  state :"none", expire:0},
        {user : "1003", pwd :"p1003", contact :"",  state :"none", expire:0},
        {user : "1004", pwd :"p1004", contact :"",  state :"none", expire:0},
        {user : "1005", pwd :"p1005", contact :"",  state :"none", expire:0}
    ]
};

//sipproxyStart(database);
//comSipBrokerStart(database);
