<script setup lang="ts">
import {computed} from 'vue'
import {NConfigProvider,NMessageProvider,NDialogProvider,darkTheme,zhCN,dateZhCN} from 'naive-ui'
import type {GlobalThemeOverrides} from 'naive-ui'
import {dark} from './store'
import ConsoleApp from './components/ConsoleApp.vue'
function createOverrides(isDark:boolean):GlobalThemeOverrides{return {
 common:{
  primaryColor:isDark?'#57b8a5':'#147d6b',primaryColorHover:isDark?'#70c6b5':'#268d7b',primaryColorPressed:isDark?'#419d8b':'#106657',
  successColor:isDark?'#66b69d':'#23836b',infoColor:isDark?'#88a7cc':'#4c729c',warningColor:isDark?'#d3ab69':'#9e742e',errorColor:isDark?'#de8585':'#b94a48',
  borderRadius:'7px',fontFamily:'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif',fontSize:'14px',
  bodyColor:isDark?'#141414':'#f6f7f8',cardColor:isDark?'#1c1c1c':'#ffffff',modalColor:isDark?'#1c1c1c':'#ffffff',tableColor:isDark?'#1c1c1c':'#ffffff',
  textColorBase:isDark?'#ededed':'#24282b',textColor1:isDark?'#ededed':'#24282b',textColor2:isDark?'#d0d0d0':'#444c54',textColor3:isDark?'#a1a1a1':'#657079',
  borderColor:isDark?'#303030':'#e5e7eb',inputColor:isDark?'#242424':'#f9fafb',actionColor:isDark?'#222222':'#f9fafb'
 },
 DataTable:{
  thColor:isDark?'#222222':'#f9fafb',thColorHover:isDark?'#282828':'#f0f2f4',thColorSorting:isDark?'#252525':'#f3f5f6',
  tdColor:isDark?'#1c1c1c':'#ffffff',tdColorHover:isDark?'#252525':'#f6f8f8',tdColorSorting:isDark?'#1e1e1e':'#fcfdfd',
  thPaddingSmall:'10px 10px',tdPaddingSmall:'7px 10px',fontSizeSmall:'14px',borderColor:isDark?'#303030':'#edf0f2'
 },Button:{fontWeight:'500'},Card:{paddingMedium:'24px'}
}}
const lightOverrides=createOverrides(false),darkOverrides=createOverrides(true)
const overrides=computed(()=>dark.value?darkOverrides:lightOverrides)
</script>
<template><NConfigProvider :theme="dark?darkTheme:null" :theme-overrides="overrides" inline-theme-disabled :locale="zhCN" :date-locale="dateZhCN"><NMessageProvider><NDialogProvider><ConsoleApp/></NDialogProvider></NMessageProvider></NConfigProvider></template>
