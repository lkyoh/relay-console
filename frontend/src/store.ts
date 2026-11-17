import { reactive,ref } from 'vue'
import type { NodeData } from './domain'
export const state=reactive({auth:'loading' as 'loading'|'login'|'ready'|'error',view:'nodes',data:{nodes:[],protocols:[]} as unknown as NodeData,traffic:{} as any,latency:{results:{},pending:[],running:false} as any,servers:null as any,connection:true,error:''})
export const dark=ref(document.documentElement.classList.contains('dark'))
let epoch=0,csrf='',polling=false
export class StaleSessionError extends Error{}
function clearSession(){epoch++;csrf='';state.auth='login';state.data={nodes:[],protocols:[]} as unknown as NodeData;state.servers=null;state.traffic={};state.latency={results:{},pending:[],running:false}}
export async function api<T=any>(path:string,body?:unknown):Promise<T>{const current=epoch,controller=new AbortController(),timer=setTimeout(()=>controller.abort(),body===undefined?15000:65000);try{const response=await fetch(path,{signal:controller.signal,method:body===undefined?'GET':'POST',headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});const value=await response.json();if(current!==epoch)throw new StaleSessionError('登录状态已变化');if(!response.ok){if(response.status===401&&path!='/api/login')clearSession();throw Error(value.error||'请求失败')}return value}catch(e){if(e instanceof DOMException&&e.name==='AbortError')throw Error('请求超时，请刷新确认当前状态');throw e}finally{clearTimeout(timer)}}
export async function refresh(){const value=await api<NodeData>('/api/nodes');csrf=value.csrf;state.data=value;state.auth='ready';state.error=''}
export async function boot(){try{await refresh();await poll()}catch(e){if(state.auth!=='login'){state.auth='error';state.error=(e as Error).message}}}
export async function login(password:string){epoch++;await api('/api/login',{password});await refresh();void poll()}
export async function logout(){try{await api('/api/logout',{})}finally{clearSession()}}
export function toggleTheme(){dark.value=!dark.value;document.documentElement.classList.toggle('dark',dark.value);try{localStorage.setItem('relay-theme',dark.value?'dark':'light')}catch{}}
export async function loadServers(){state.servers=await api('/api/servers')}
export async function poll(){if(polling||state.auth!=='ready'||document.hidden)return;polling=true;const current=epoch;try{const jobs=await Promise.allSettled([api('/api/traffic'),api('/api/latency'),...(state.view==='servers'?[api('/api/servers')]:[])]);if(current!==epoch)return;if(jobs[0].status==='fulfilled'){state.traffic=jobs[0].value;state.connection=true;if(typeof state.traffic.service_active==='boolean')state.data.active=state.traffic.service_active}else state.connection=false;if(jobs[1].status==='fulfilled')state.latency=jobs[1].value;if(jobs[2]?.status==='fulfilled')state.servers=jobs[2].value}catch{}finally{polling=false}}
export async function testLatency(ids:string[]){if(!ids.length||state.latency.running)return;await api('/api/latency/test',{ids});state.latency={...state.latency,running:true,pending:ids,total:ids.length,completed:0};void poll()}
export async function copy(text:string){await navigator.clipboard.writeText(text)}
export function download(text:string,name:string,type='text/plain;charset=utf-8'){const u=URL.createObjectURL(new Blob([text],{type})),a=document.createElement('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}
