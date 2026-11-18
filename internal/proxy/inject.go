package proxy

import (
	"encoding/json"
	"strings"

	"github.com/SaaelCompany/tlswitch/internal/rewrite"
)

func injectTag(mode rewrite.Mode, host string, suffixes []string) string {
	kind := "path"
	if mode == rewrite.ModeHost {
		kind = "host"
	}
	dotted := make([]string, len(suffixes))
	for i, s := range suffixes {
		dotted[i] = "." + strings.TrimPrefix(s, ".")
	}
	payload, _ := json.Marshal(map[string]any{
		"mode":     kind,
		"host":     host,
		"suffixes": dotted,
	})
	return `<script data-tlswitch="1">` + injectJS + `(` + string(payload) + `)</script>`
}

const injectJS = `(function(cfg){
  function allowed(host){
    host=(host||"").toLowerCase().replace(/\.$/,"");
    var list=cfg.suffixes||[];
    for(var i=0;i<list.length;i++){
      var s=list[i];
      var bare=s.charAt(0)==="."?s.slice(1):s;
      if(host===bare||host.endsWith(s)) return true;
    }
    return false;
  }
  function map(u){
    try{
      var url=new URL(u, location.href);
      if(cfg.mode==="path"){
        if(url.origin===location.origin){
          if(url.pathname.indexOf("/go/")===0) return url.toString();
          return location.origin+"/go/"+cfg.host+url.pathname+url.search+url.hash;
        }
        if(url.protocol==="https:"||url.protocol==="http:"){
          return location.origin+"/go/"+url.host+url.pathname+url.search+url.hash;
        }
        if(url.protocol==="wss:"||url.protocol==="ws:"){
          var ws=location.protocol==="https:"?"wss://":"ws://";
          return ws+location.host+"/go/"+url.host+url.pathname+url.search;
        }
      }else if((url.protocol==="https:"||url.protocol==="wss:")&&allowed(url.hostname)){
        url.protocol=url.protocol==="https:"?"http:":"ws:";
        return url.toString();
      }
    }catch(e){}
    return u;
  }
  var ofetch=window.fetch;
  if(ofetch){
    window.fetch=function(input, init){
      if(typeof input==="string") input=map(input);
      else if(input&&input.url){
        try{ input=new Request(map(input.url), input); }catch(e){}
      }
      return ofetch.call(this, input, init);
    };
  }
  var xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(method, url){
    arguments[1]=map(url);
    return xo.apply(this, arguments);
  };
  var OWS=window.WebSocket;
  if(OWS){
    var WS=function(url, protocols){
      return protocols===undefined?new OWS(map(url)):new OWS(map(url), protocols);
    };
    WS.prototype=OWS.prototype;
    window.WebSocket=WS;
  }
  ["assign","replace"].forEach(function(name){
    var orig=Location.prototype[name];
    if(!orig) return;
    Location.prototype[name]=function(u){ return orig.call(this, map(u)); };
  });
  try{
    var desc=Object.getOwnPropertyDescriptor(Location.prototype,"href");
    if(desc&&desc.set){
      Object.defineProperty(Location.prototype,"href",{
        configurable:true,
        enumerable:desc.enumerable,
        get:desc.get,
        set:function(v){ return desc.set.call(this, map(v)); }
      });
    }
  }catch(e){}
  if(window.history){
    var ps=history.pushState, rs=history.replaceState;
    history.pushState=function(s,t,u){ return ps.call(history,s,t,u==null?u:map(u)); };
    history.replaceState=function(s,t,u){ return rs.call(history,s,t,u==null?u:map(u)); };
  }
  document.addEventListener("click", function(e){
    var n=e.target;
    if(!n||!n.closest) return;
    var a=n.closest("a[href]");
    if(!a) return;
    var href=a.getAttribute("href");
    var nu=map(href);
    if(nu!==href) a.setAttribute("href", nu);
  }, true);
  document.addEventListener("submit", function(e){
    var f=e.target;
    if(!f||!f.getAttribute) return;
    var action=f.getAttribute("action");
    if(!action) return;
    var nu=map(action);
    if(nu!==action) f.setAttribute("action", nu);
  }, true);
  if(cfg.mode==="path" && navigator.serviceWorker){
    var reg=navigator.serviceWorker.register.bind(navigator.serviceWorker);
    navigator.serviceWorker.register=function(){
      return Promise.resolve({unregister:function(){return Promise.resolve(false);}});
    };
    reg("/go/sw.js",{scope:"/go/"}).catch(function(){});
  }
})`

const serviceWorkerJS = `"use strict";
self.addEventListener("install", function(){ self.skipWaiting(); });
self.addEventListener("activate", function(event){ event.waitUntil(self.clients.claim()); });
self.addEventListener("fetch", function(event){
  var req = event.request;
  var url;
  try { url = new URL(req.url); } catch (e) { return; }
  if (url.origin === self.location.origin && (url.pathname.indexOf("/go/") === 0)) return;
  if (url.protocol !== "http:" && url.protocol !== "https:") return;
  event.respondWith((async function(){
    var target;
    if (url.origin !== self.location.origin) {
      target = self.location.origin + "/go/" + url.host + url.pathname + url.search;
    } else {
      var host = "";
      try {
        var client = event.clientId ? await self.clients.get(event.clientId) : null;
        if (client) {
          var parts = new URL(client.url).pathname.split("/");
          host = parts[2] || "";
        }
      } catch (e) {}
      if (!host) return fetch(req);
      target = self.location.origin + "/go/" + host + url.pathname + url.search;
    }
    try { return await fetch(new Request(target, req)); }
    catch (e) { return fetch(req); }
  })());
});
`
