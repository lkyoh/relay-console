import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest'
import {filterNodes,linksOf,nameOf,createPreviewGuard} from './domain'
import type {RelayNode} from './domain'
const node:RelayNode={id:'a',name:'one',display_names:{reality:'1.1.1.1-VLESS-Reality',hysteria2:'1.1.1.1-Hysteria2'},server:'1.1.1.1',socks_port:443,port:32001,enabled:true,links:{reality:'vless://one',hysteria2:'hysteria2://one'},ports:{reality:32001,hysteria2:33001}}
describe('node interactions',()=>{
 it('filters protocol names, ports and auto display names',()=>{expect(filterNodes([node],'33001','all')).toHaveLength(1);expect(filterNodes([node],'hysteria2','all')).toHaveLength(1);expect(filterNodes([node],'','disabled')).toHaveLength(0)})
 it('exports only selected protocol without a fallback to disabled protocols',()=>{expect(linksOf(node,'reality')).toEqual(['vless://one']);expect(linksOf(node,'tuic')).toEqual([]);expect(linksOf(node,'all')).toHaveLength(2);expect(nameOf(node,'hysteria2')).toBe('1.1.1.1-Hysteria2')})
 it('invalidates a preview immediately when the bulk input changes',()=>{const g=createPreviewGuard(),v=g.capture();g.invalidate();expect(g.valid(v)).toBe(false);expect(g.valid(g.capture())).toBe(true)})
})
describe('session isolation',()=>{
 beforeEach(()=>{vi.resetModules();vi.stubGlobal('document',{createElement:()=>({}),hidden:false,documentElement:{classList:{contains:()=>false}}})})
 afterEach(()=>vi.unstubAllGlobals())
 it('drops an old successful request after logout',async()=>{const store=await import('./store');let finish:any;vi.stubGlobal('fetch',vi.fn((path)=>path==='/api/logout'?Promise.resolve({ok:true,json:async()=>({ok:true})}):new Promise(r=>finish=r)));const pending=store.api('/slow');await store.logout();finish({ok:true,json:async()=>({private:true})});await expect(pending).rejects.toBeInstanceOf(store.StaleSessionError)})
 it('does not apply a fulfilled traffic result when logout occurs while another poll request is pending',async()=>{const store=await import('./store');store.state.auth='ready';let finish:any;vi.stubGlobal('fetch',vi.fn(path=>path==='/api/traffic'?Promise.resolve({ok:true,json:async()=>({private:true})}):path==='/api/logout'?Promise.resolve({ok:true,json:async()=>({ok:true})}):new Promise(r=>finish=r)));const pending=store.poll();await new Promise(r=>setTimeout(r,0));await store.logout();finish({ok:true,json:async()=>({results:{}})});await pending;expect(store.state.traffic).toEqual({});expect(store.state.auth).toBe('login')})
 it('shows login only after an actual unauthorized response',async()=>{const store=await import('./store');expect(store.state.auth).toBe('loading');vi.stubGlobal('fetch',vi.fn(async()=>({ok:false,status:401,json:async()=>({error:'请先登录'})})));await store.boot();expect(store.state.auth).toBe('login')})
})

