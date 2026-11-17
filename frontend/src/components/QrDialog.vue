<script setup lang="ts">
import { computed,ref } from 'vue'
import {NModal,NSelect,NInput,NButton,NSpace,useMessage} from 'naive-ui'
import qrcode from 'qrcode-generator'
import {copy} from '../store'
const props=defineProps<{show:boolean;title:string;links:Record<string,string>;initial?:string}>();const emit=defineEmits(['update:show']);const protocol=ref('');const message=useMessage()
const current=computed(()=>props.links[protocol.value]?protocol.value:props.initial&&props.links[props.initial]?props.initial:Object.keys(props.links)[0]);const value=computed(()=>props.links[current.value]||'')
const svg=computed(()=>{if(!value.value)return '';const q=qrcode(0,'M');q.addData(value.value);q.make();return q.createSvgTag({cellSize:4,margin:16,scalable:true})})
async function png(){try{const q=qrcode(0,'M');q.addData(value.value);q.make();const count=q.getModuleCount(),scale=Math.max(1,Math.floor(1024/(count+8))),canvas=document.createElement('canvas');canvas.width=canvas.height=(count+8)*scale;const ctx=canvas.getContext('2d')!;ctx.fillStyle='#fff';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle='#000';for(let r=0;r<count;r++)for(let c=0;c<count;c++)if(q.isDark(r,c))ctx.fillRect((c+4)*scale,(r+4)*scale,scale,scale);const a=document.createElement('a');a.href=canvas.toDataURL('image/png');a.download=props.title.replace(/[<>:"/\\|?*]/g,'_')+'.png';a.click()}catch{message.error('二维码图片生成失败')}}
</script>
<template><NModal :show="show" @update:show="emit('update:show',$event)" preset="card" :title="title+' · 二维码'" class="dialog qr-dialog"><NSelect :value="current" @update:value="protocol=$event" :options="Object.keys(links).map(p=>({value:p,label:p==='reality'?'VLESS Reality':p==='all'?'全部协议':p}))"/><div class="qr-code" v-html="svg"/><NInput :value="value" type="textarea" readonly :autosize="{minRows:2,maxRows:4}"/><template #footer><NSpace justify="end"><NButton @click="png">保存 PNG</NButton><NButton type="primary" @click="copy(value).then(()=>message.success('已复制')).catch(()=>message.error('剪贴板不可用'))">复制链接</NButton></NSpace></template></NModal></template>
