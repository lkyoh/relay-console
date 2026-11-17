<script setup lang="ts">
import {computed} from 'vue'
import {NConfigProvider,NMessageProvider,NDialogProvider,darkTheme,zhCN,dateZhCN} from 'naive-ui'
import type {GlobalThemeOverrides} from 'naive-ui'
import {dark} from './store'
import ConsoleApp from './components/ConsoleApp.vue'
const overrides=computed<GlobalThemeOverrides>(()=>({
 common:{
  primaryColor:dark.value?'#57b8a5':'#147d6b',primaryColorHover:dark.value?'#70c6b5':'#268d7b',primaryColorPressed:dark.value?'#419d8b':'#106657',
  successColor:dark.value?'#66b69d':'#23836b',infoColor:dark.value?'#88a7cc':'#4c729c',warningColor:dark.value?'#d3ab69':'#9e742e',errorColor:dark.value?'#de8585':'#b94a48',
  borderRadius:'7px',fontFamily:'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif',fontSize:'14px',
  bodyColor:dark.value?'#141414':'#f6f7f8',cardColor:dark.value?'#1c1c1c':'#ffffff',modalColor:dark.value?'#1c1c1c':'#ffffff',tableColor:dark.value?'#1c1c1c':'#ffffff',
  textColorBase:dark.value?'#ededed':'#24282b',textColor1:dark.value?'#ededed':'#24282b',textColor2:dark.value?'#d0d0d0':'#444c54',textColor3:dark.value?'#a1a1a1':'#657079',
  borderColor:dark.value?'#303030':'#e5e7eb',inputColor:dark.value?'#242424':'#f9fafb',actionColor:dark.value?'#222222':'#f9fafb'
 },
 DataTable:{
  thColor:dark.value?'#222222':'#f9fafb',thColorHover:dark.value?'#282828':'#f0f2f4',thColorSorting:dark.value?'#252525':'#f3f5f6',
  tdColor:dark.value?'#1c1c1c':'#ffffff',tdColorHover:dark.value?'#252525':'#f6f8f8',tdColorSorting:dark.value?'#1e1e1e':'#fcfdfd',
  thPaddingSmall:'10px 10px',tdPaddingSmall:'7px 10px',fontSizeSmall:'14px',borderColor:dark.value?'#303030':'#edf0f2'
 },Button:{fontWeight:'500'},Card:{paddingMedium:'24px'}
}))
</script>
<template><NConfigProvider :theme="dark?darkTheme:null" :theme-overrides="overrides" :locale="zhCN" :date-locale="dateZhCN"><NMessageProvider><NDialogProvider><ConsoleApp/></NDialogProvider></NMessageProvider></NConfigProvider></template>
