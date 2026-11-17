import { shallowReactive,ref,nextTick } from 'vue'
import {shareSnapshot} from './snapshot'
import type { NodeData,GeoLocation } from './domain'
export const state=shallowReactive({auth:'loading' as 'loading'|'login'|'ready'|'error',view:'nodes',data:{nodes:[],protocols:[]} as unknown as NodeData,traffic:{} as any,locations:{} as Record<string,GeoLocation>,latency:{results:{},pending:[],running:false} as any,servers:null as any,connection:true,error:''})
export const dark=ref(document.documentElement.classList.contains('dark'))
let epoch=0,csrf='',polling=false,latencyAt=0,themeVersion=0,latencyVersion=0,geoAt=0,geoPending=true,geoBusy=false
export class StaleSessionError extends Error{}
function clearSession(){geoAt=0;geoPending=true;state.locations={};latencyAt=0;epoch++;csrf='';state.auth='login';state.data={nodes:[],protocols:[]} as unknown as NodeData;state.servers=null;state.traffic={};state.latency={results:{},pending:[],running:false}}
export async function api<T=any>(path:string,body?:unknown):Promise<T>{const current=epoch,controller=new AbortController(),timer=setTimeout(()=>controller.abort(),body===undefined?15000:65000);try{const response=await fetch(path,{signal:controller.signal,method:body===undefined?'GET':'POST',headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});const value=await response.json();if(current!==epoch)throw new StaleSessionError('登录状态已变化');if(!response.ok){if(response.status===401&&path!='/api/login')clearSession();throw Error(value.error||'请求失败')}return value}catch(e){if(e instanceof DOMException&&e.name==='AbortError')throw Error('请求超时，请刷新确认当前状态');throw e}finally{clearTimeout(timer)}}
export async function refresh(){const value=await api<NodeData>('/api/nodes');csrf=value.csrf;state.data=shareSnapshot(state.data,value);state.auth='ready';state.error=''}
export async function boot(){try{await refresh();await poll()}catch(e){if(state.auth!=='login'){state.auth='error';state.error=(e as Error).message}}}
export async function login(password:string){epoch++;await api('/api/login',{password});await refresh();void poll()}
export async function logout(){try{await api('/api/logout',{})}finally{clearSession()}}
export function toggleTheme(){
 const version=++themeVersion,root=document.documentElement
 root.classList.add('theme-switching');dark.value=!dark.value;root.classList.toggle('dark',dark.value)
 try{localStorage.setItem('relay-theme',dark.value?'dark':'light')}catch{}
 void nextTick(()=>requestAnimationFrame(()=>requestAnimationFrame(()=>{if(version===themeVersion)root.classList.remove('theme-switching')})))
}
export async function loadServers(){state.servers=shareSnapshot(state.servers,await api('/api/servers'))}
export async function poll(){
 if(polling||state.auth!=='ready'||document.hidden)return
 polling=true;const current=epoch,latencyEpoch=latencyVersion,checkLatency=state.latency.running||state.view==='nodes'&&Date.now()-latencyAt>=30000
 try{
  const jobs=await Promise.allSettled([api('/api/traffic'),checkLatency?api('/api/latency'):Promise.resolve(null),state.view==='servers'?api('/api/servers'):Promise.resolve(null)])
  if(current!==epoch)return
  if(jobs[0].status==='fulfilled'){
   state.traffic=shareSnapshot(state.traffic,jobs[0].value);state.connection=true
   if(typeof state.traffic.service_active==='boolean'&&state.data.active!==state.traffic.service_active)state.data={...state.data,active:state.traffic.service_active}
  }else state.connection=false
  if(latencyEpoch===latencyVersion&&jobs[1].status==='fulfilled'&&jobs[1].value){state.latency=shareSnapshot(state.latency,jobs[1].value);latencyAt=Date.now()}
  if(jobs[2].status==='fulfilled'&&jobs[2].value)state.servers=shareSnapshot(state.servers,jobs[2].value)
 }finally{polling=false}
}
export async function testLatency(ids:string[]){if(!ids.length||state.latency.running)return;await api('/api/latency/test',{ids});latencyVersion++;latencyAt=0;state.latency={...state.latency,running:true,pending:ids,total:ids.length,completed:0};void poll()}
export async function copy(text:string){await navigator.clipboard.writeText(text)}
export function download(text:string,name:string,type='text/plain;charset=utf-8'){const u=URL.createObjectURL(new Blob([text],{type})),a=document.createElement('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}

export async function pollGeo(force=false){
 if(geoBusy||state.auth!=='ready'||!force&&(document.hidden||!geoPending&&Date.now()-geoAt<30000))return
 geoBusy=true
 try{const v=await api('/api/geo');state.locations=shareSnapshot(state.locations,v.locations||{});geoPending=!!v.pending;geoAt=Date.now()}catch{}finally{geoBusy=false}
}
