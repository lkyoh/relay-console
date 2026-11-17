<script setup lang="ts">
import {computed} from 'vue'
import {state} from '../store'
import {bytes} from '../domain'
const enabled=computed(()=>state.data.nodes.filter(n=>n.enabled).length),count=computed(()=>state.data.nodes.length)
const down=computed(()=>bytes(state.traffic.available?Object.values(state.traffic.rates||{}).reduce((a:number,r:any)=>a+(r.download||0),0) as number:undefined,true))
const up=computed(()=>bytes(state.traffic.available?Object.values(state.traffic.rates||{}).reduce((a:number,r:any)=>a+(r.upload||0),0) as number:undefined,true))
const total=computed(()=>bytes(Object.values(state.traffic.totals||{}).reduce((a:number,t:any)=>a+(t.download||0)+(t.upload||0),0) as number))
</script>
<template><div class="metrics"><article><span>运行节点</span><strong>{{enabled}}<small>/ {{count}}</small></strong><footer>当前已启用线路</footer></article><article><span>实时下载</span><strong>{{down}}</strong><footer>每 2 秒更新</footer></article><article><span>实时上传</span><strong>{{up}}</strong><footer>每 2 秒更新</footer></article><article><span>累计流量</span><strong>{{total}}</strong><footer>跨重启保留统计</footer></article></div></template>
