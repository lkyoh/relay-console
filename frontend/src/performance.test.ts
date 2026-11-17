import {describe,it,expect,vi,afterEach} from 'vitest'
import {computed,watchEffect,nextTick} from 'vue'
import {shareSnapshot} from './snapshot'
describe('polling performance',()=>{
 afterEach(()=>vi.unstubAllGlobals())
 it('reuses unchanged snapshots and preserves unmodified branches',()=>{
  const before={sampled_at:1,rates:{a:{download:0,upload:0},b:{download:1,upload:0}}}
  expect(shareSnapshot(before,structuredClone(before))).toBe(before)
  const after=shareSnapshot(before,{sampled_at:2,rates:{a:{download:0,upload:0},b:{download:2,upload:0}}})
  expect(after).not.toBe(before);expect(after.rates.a).toBe(before.rates.a);expect(after.rates.b).not.toBe(before.rates.b)
 })
 it('does not rerender an unchanged cell when another node or timestamp changes',async()=>{
  vi.stubGlobal('document',{createElement:()=>({}),hidden:false,documentElement:{classList:{contains:()=>false}}})
  const {state}=await import('./store');state.traffic={rates:{a:{download:0},b:{download:1}}}
  const value=computed(()=>state.traffic.rates.a.download);let renders=0;const stop=watchEffect(()=>{void value.value;renders++})
  state.traffic=shareSnapshot(state.traffic,{sampled_at:2,rates:{a:{download:0},b:{download:2}}});await nextTick();expect(renders).toBe(1)
  state.traffic=shareSnapshot(state.traffic,{sampled_at:3,rates:{a:{download:5},b:{download:2}}});await nextTick();expect(renders).toBe(2);stop()
 })
 it('skips redundant idle latency requests while keeping traffic polling',async()=>{
  vi.resetModules();vi.stubGlobal('document',{createElement:()=>({}),hidden:false,documentElement:{classList:{contains:()=>false}}})
  const store=await import('./store');store.state.auth='ready'
  const fetch=vi.fn(async(path:string)=>({ok:true,json:async()=>path==='/api/latency'?{results:{},pending:[],running:false}:{available:true,rates:{},totals:{}}}));vi.stubGlobal('fetch',fetch)
  await store.poll();await store.poll();expect(fetch.mock.calls.filter(x=>x[0]==='/api/traffic')).toHaveLength(2);expect(fetch.mock.calls.filter(x=>x[0]==='/api/latency')).toHaveLength(1)
  store.state.latency={...store.state.latency,running:true};await store.poll();expect(fetch.mock.calls.filter(x=>x[0]==='/api/latency')).toHaveLength(2)
 })
 it('does not overwrite a newly started latency test with an older idle response',async()=>{
  vi.resetModules();vi.stubGlobal('document',{createElement:()=>({}),hidden:false,documentElement:{classList:{contains:()=>false}}})
  const store=await import('./store');store.state.auth='ready';let finishTraffic:any
  vi.stubGlobal('fetch',vi.fn((path:string)=>path==='/api/traffic'?new Promise(r=>finishTraffic=r):Promise.resolve({ok:true,json:async()=>path==='/api/latency'?{results:{},pending:[],running:false}:{ok:true}})))
  const pending=store.poll();await new Promise(r=>setTimeout(r,0));await store.testLatency(['a'])
  finishTraffic({ok:true,json:async()=>({available:true})});await pending
  expect(store.state.latency.running).toBe(true);expect(store.state.latency.pending).toEqual(['a'])
 })
 it('coalesces rapid theme changes and always removes the temporary transition guard',async()=>{
  vi.resetModules();const classes=new Set<string>(),frames:Array<()=>void>=[]
  vi.stubGlobal('document',{createElement:()=>({}),hidden:false,documentElement:{classList:{contains:(x:string)=>classes.has(x),add:(x:string)=>classes.add(x),remove:(x:string)=>classes.delete(x),toggle:(x:string,v:boolean)=>v?classes.add(x):classes.delete(x)}}})
  vi.stubGlobal('requestAnimationFrame',(fn:()=>void)=>{frames.push(fn);return frames.length});vi.stubGlobal('localStorage',{setItem:vi.fn()})
  const store=await import('./store');store.toggleTheme();store.toggleTheme();await nextTick();expect(classes.has('theme-switching')).toBe(true)
  while(frames.length)frames.shift()!();expect(classes.has('theme-switching')).toBe(false);expect(store.dark.value).toBe(false)
 })
})
