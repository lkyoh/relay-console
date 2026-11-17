import {computed,defineComponent,h} from 'vue'
import {NButton} from 'naive-ui'
import {state} from '../store'
import {bytes} from '../domain'
export const FlowCell=defineComponent({props:{id:{type:String,required:true},kind:{type:String,required:true}},setup(props){
 const available=computed(()=>props.kind!=='rate'||!!state.traffic.available)
 const down=computed(()=>bytes(!available.value?undefined:(props.kind==='rate'?state.traffic.rates:state.traffic.totals)?.[props.id]?.download||0,props.kind==='rate'))
 const up=computed(()=>bytes(!available.value?undefined:(props.kind==='rate'?state.traffic.rates:state.traffic.totals)?.[props.id]?.upload||0,props.kind==='rate'))
 return ()=>h('div',{class:'flow'},[h('span',{},'↓ '+down.value),h('span',{class:'muted'},'↑ '+up.value)])
}})
export const LatencyCell=defineComponent({props:{id:{type:String,required:true},test:{type:Function,required:true}},setup(props){
 const pending=computed(()=>state.latency.pending.includes(props.id)),running=computed(()=>state.latency.running)
 const ms=computed(()=>state.latency.results[props.id]?.ms),error=computed(()=>state.latency.results[props.id]?.error)
 return ()=>h(NButton,{text:true,size:'small',disabled:running.value,type:ms.value===null?'error':ms.value>1500?'warning':ms.value!==undefined?'success':undefined,title:error.value||'服务器到落地的 HTTPS 延迟',onClick:()=>props.test([props.id])},()=>pending.value?'测试中':ms.value===null?'失败':ms.value===undefined?'测试':ms.value+' ms')
}})
