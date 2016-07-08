const request = require('request');
const forge = require('node-forge');
const os = require('os');
const fs = require('fs');
const path = require('path');
const allowedHashTypes = ['sha256', 'sha384', 'sha512'];

var hosts = {}

function Request(){
	return request.apply(this, arguments).on('response', onResponse).on('socket', onSocket);
}

function makeHelper(obj, verb) {

	obj[verb] = function helper() {

		var f = null;
		var options = {
			method: verb.toUpperCase(),
		}

		for (var i in arguments){
			var argument = arguments[i];

			switch(typeof argument){

				case 'function':
				f = argument;
				break;

				case 'string':
				options.uri =  argument;
				break;

				case 'object':
				for (var k in argument){
					options[k] = argument[k];
				}
				break;

			}

		}

		if (f){
			return obj(options, f);
		}
		
		return obj(options);
	};
}

var verbs = ['get', 'head', 'post', 'put', 'patch', 'delete', 'del'];
for (var k in request){

	if (typeof request[k] !== 'function'){
		continue;
	}

	if (verbs.indexOf(k) == -1){
		Request[k] = request[k];
	} else {
		makeHelper(Request, k);
	} 

}

function onSocket(socket){

	socket.on('secureConnect', function(){

		var cached = cacheHosts.get(this.uri.hostname);
		if (!cached){
			return;
		}

		if (!socket.authorized){
			socket.emit('error', new Error(socket.authorizationError));
			this.abort();
			return;
		}

		if (!socket.getPeerCertificate().raw){
			return;
		}

		var base64 = socket.getPeerCertificate().raw.toString('base64');
		var obj = forge.asn1.fromDer(forge.util.decode64(base64));
		var cert = forge.pki.certificateFromAsn1(obj);
		var pubCertAsn1 = forge.pki.publicKeyToAsn1(cert.publicKey);
		var derPub = forge.asn1.toDer(pubCertAsn1).getBytes();

		for (var k in cached.keys){

			var currentKey = cached.keys[k];

			if (allowedHashTypes.indexOf(currentKey.hashType) == -1){
				this.emit('error', new Error('HPKP verification error, invalid hash type' + currentKey.hashType));
			}

			var md = forge.md[currentKey.hashType].create();
			md.update(derPub);
			var signature = forge.util.encode64(md.digest().bytes());

			if (signature === currentKey.value){
				return;
			}

		}
		
		if (cached.reportUri){
			reportUri(cached, this.uri.hostname, this.uri.port);
		}

		if (cached.reportOnly){
			return;
		}

		for (var k in socket._httpMessage.agent._sessionCache.map){

			if (socket.getSession().toString() == socket._httpMessage.agent._sessionCache.map[k].toString()){
				delete socket._httpMessage.agent._sessionCache.map[k];
				socket._httpMessage.agent._sessionCache.list.splice(socket._httpMessage.agent._sessionCache.list.indexOf(k),1);
			}
		}

		this.emit('error', new Error('HPKP verification error'));
		this.abort();

	}.bind(this));
}

function reportUri(cache, hostname, port){

	var knownPins = [];
	for (var i in cache.keys){
		knownPins.push('pin-'+cache.keys[i].hashType+'="'+cache.keys[i].value+'"');
	}

	var postData = {
		'date-time': new Date(),
		'hostname': hostname,
		'port': port,
		'include-subdomains': cache.includeSubdomains,
		'known-pins': knownPins
	}

	request.post(cache.reportUri, {json:true, body: postData});
}

function extractHeader(from){

	if (!from){
		return false;
	}

	var a = from.split(';');
	var h = {keys:[], ttl: 0};

	for (var i in a){
		a[i] = a[i].trim();
		var match = (a[i].match(/pin-([0-9-a-z]*)\=\"(.*\=*)\"/i));
		if (match){
			h.keys.push({hashType: match[1], value: match[2]});
		} else {
			var t = a[i].split('=');

			switch(t[0]){
				case 'max-age':
				h.ttl = parseInt(t[1]);
				break;

				case 'report-uri':
				h.reportUri = t[1].replace('"','').trim();
				break;

				case 'includeSubdomains':
				h.includeSubdomains = true;
				break;
			}

		}
	}

	if (h.keys.length < 2){
		return false;
	}

	if (!h.ttl){
		return false;
	}

	return h;
}

function onResponse(res){

	if (res.request.uri.protocol != 'https:' || !res.headers['public-key-pins']){
		return;
	}

	var extractedEnforce = extractHeader(res.headers['public-key-pins']);
	var extractedReportOnly = extractHeader(res.headers['public-key-pins-report-only']);

	if (extractedReportOnly){
		extractedReportOnly.reportOnly = true;
		cacheHosts.set(res.request.host, extractedReportOnly);
	}

	if (extractedEnforce){
		cacheHosts.set(res.request.host, extractedEnforce);
	}

}

var cacheHosts = {
	path: null,

	get: function(hostname){

		if (!hosts){return;}		

		var host = hosts[hostname];
		if (!host){
			return;
		}

		if (host.expiresAt < Math.ceil(new Date().getTime()/1000)){
			delete hosts[hostname];
			return;
		}

		return host;
	},

	set: function(hostname, data){

		if (hosts[hostname]){
			return;
		}

		data.expiresAt = Math.ceil(new Date().getTime()/1000) + data.ttl;

		hosts[hostname] = data;

		if (!this.path){
			return;
		}

		var savePath = path.join(this.path, hostname+'.hpkp.json');
		fs.writeFile(savePath, JSON.stringify(data), function(err){
			if (err){
				throw new Error('Could not save hpkp cache file: ' + savePath);
			}
		});

	},

	load: function(){
		if (!this.path){
			return;
		}

		var files = fs.readdirSync(this.path);
		for (var i in files){
			var file = files[i];
			if (file.indexOf('.hpkp.json') == -1){
				continue;
			}

			var json = null;
			try{
				var json = JSON.parse(fs.readFileSync(path.join(this.path, file)).toString());
			} catch (E){
				json = false;
			}

			if (!json){
				continue;
			}

			var hostname = file.replace('.hpkp.json', '');
			hosts[hostname] = json;

		}

	}
}

Request.hpkpCache = function(config){
	if (typeof config === 'object'){

		if (!config.set || !config.get){
			throw new Error('hpkpCache requires both set and get functions');
		}

		cacheHosts = config;

	} else {
		if (!config){
			config = os.tmpdir();
		}
		cacheHosts.path = config;
		cacheHosts.load();
	}
};

module.exports = Request;