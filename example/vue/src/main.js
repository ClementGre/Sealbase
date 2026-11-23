import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import { router } from './router/index.js'
import { initSession } from './sealbase.js'

initSession().finally(() => {
  createApp(App).use(router).mount('#app')
})
