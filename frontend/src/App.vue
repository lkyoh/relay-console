<script setup lang="ts">
import {computed} from 'vue'
import {NConfigProvider,NMessageProvider,NDialogProvider,darkTheme,zhCN,dateZhCN} from 'naive-ui'
import {dark} from './store'
import ConsoleApp from './components/ConsoleApp.vue'
const overrides=computed(()=>({common:{primaryColor:dark.value?'#2dd4bf':'#0d9488',primaryColorHover:dark.value?'#5eead4':'#0f766e',primaryColorPressed:'#0f766e',borderRadius:'7px',fontFamily:'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif',fontSize:'14px',bodyColor:dark.value?'#101318':'#f5f7fa',cardColor:dark.value?'#171c23':'#ffffff',modalColor:dark.value?'#171c23':'#ffffff',tableColor:dark.value?'#171c23':'#ffffff',textColorBase:dark.value?'#e7edf5':'#17212f'},DataTable:{thColor:dark.value?'#1b222b':'#f8fafc',tdColor:dark.value?'#171c23':'#fff',tdColorHover:dark.value?'#1d2630':'#f4f9f9',thPaddingSmall:'10px 10px',tdPaddingSmall:'7px 10px',fontSizeSmall:'14px',borderColor:dark.value?'#28313b':'#edf0f3'},Button:{fontWeight:'500'},Card:{paddingMedium:'24px'}}))
</script>
<template><NConfigProvider :theme="dark?darkTheme:null" :theme-overrides="overrides" :locale="zhCN" :date-locale="dateZhCN"><NMessageProvider><NDialogProvider><ConsoleApp/></NDialogProvider></NMessageProvider></NConfigProvider></template>
