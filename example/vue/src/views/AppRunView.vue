<script setup>
// Full-screen host for one app instance at its own URL (/<slug> or
// /<slug>/<index>), so back and reload behave normally. Renders only the
// app component and hands it the instance as an `app` prop (an AppHandle);
// sharing/rename/delete live at /manage/:id. Apps may include the optional
// AppTopBar themselves.
import { ref, shallowRef, computed, watch, markRaw } from 'vue'
import { useRoute } from 'vue-router'
import { client, sortByCreation } from '../sealbase.js'
import { errorMessage } from '../errors.js'
import { getAppDefinition } from '../apps/registry.js'

const route = useRoute()
const slug = computed(() => route.params.slug)
const index = computed(() => Number(route.params.index || 0))

const app = shallowRef(null)
const loading = ref(true)
const error = ref('')
const definition = computed(() => getAppDefinition(slug.value))

async function load() {
  loading.value = true
  error.value = ''
  app.value = null
  try {
    const match = sortByCreation(await client.listApps(slug.value))[index.value]
    if (!match) {
      error.value = `No app found at /${slug.value}${index.value ? '/' + index.value : ''}`
      return
    }
    app.value = markRaw(await client.getApp(match.id))
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}

watch([slug, index], load, { immediate: true })
</script>

<template>
  <p v-if="error" class="p-4 text-sm text-red-700">{{ error }}</p>
  <p v-else-if="loading" class="p-4 text-sm text-neutral-500">Loading…</p>
  <p v-else-if="app && !definition" class="p-4 text-sm text-red-600">No app registered for slug "{{ app.slug }}".</p>
  <component
    :is="definition.component"
    v-else-if="app && definition"
    :key="app.id"
    :app="app"
    :icon="definition.icon"
    :color="definition.color"
    :display-name="definition.displayName"
  />
</template>
