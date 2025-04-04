<template>
  <v-container class="fill-height d-flex flex-column">
    <v-card-title>Логи</v-card-title>
    <v-data-table
        :headers="headers"
        :items="logs"
        class="elevation-1 flex-grow-1"
        density="comfortable"
    >
      <template v-slot:item.timestamp="{ item }">
        {{ formatTimestamp(item.timestamp) }}
      </template>
      <!-- Поле "Адрес источника" -->
      <template v-slot:item.source="{ item }">
        {{ item.source_addr_v4 }}:{{ item.source_port }}
      </template>

      <!-- Поле "Адрес назначения" -->
      <template v-slot:item.destination="{ item }">
        {{ item.destination_addr_v4 }}:{{ item.destination_port }}
      </template>

      <!-- Поле "Действие" с иконками -->
      <template v-slot:item.action="{ item }">
        <v-icon :color="item.action === 'Drop' ? 'red' : 'green'">
          {{ item.action === 'Drop' ? 'mdi-close-circle' : 'mdi-check-circle' }}
        </v-icon>
      </template>

      <!-- Поле "Тип траффика" с иконками -->
      <template v-slot:item.traffic_type="{ item }">
        <v-icon :color="'blue'">
          {{ item.traffic_type === 'Output' ? 'mdi-arrow-right' : 'mdi-arrow-left' }}
        </v-icon>
      </template>
    </v-data-table>
  </v-container>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted } from "vue";
import { useStore } from "vuex";
import dayjs from "dayjs";

const store = useStore();
let ws: WebSocket | null = null;

const headers = [
  { title: "Время", key: "timestamp" },
  { title: "Тип траффика", key: "traffic_type" },
  { title: "Сетевой интерфейс", key: "if_name" },
  { title: "Адрес источника", key: "source" }, // Объединённое поле IP:PORT
  { title: "Адрес назначения", key: "destination" }, // Объединённое поле IP:PORT
  { title: "Правило", key: "rule_name" },
  { title: "Действие", key: "action" },
];


const logs = computed(() => store.getters["logs/logs"]);

const formatTimestamp = (ts: number) => {
  return dayjs.unix(ts).format("YYYY-MM-DD HH:mm:ss");
};

const connectWebSocket = () => {
  ws = new WebSocket("ws://127.0.0.1:8080/ws/logs");

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      console.log(data);
      store.dispatch("logs/addLog", data);
    } catch (error) {
      console.error("ws.onmessage.ERROR:", error);
    }
  };

  ws.onerror = (error) => console.error("ws.onerror:", error);
  ws.onclose = () => {
    setTimeout(connectWebSocket, 5000);
  };
};

onMounted(() => {
  connectWebSocket();
});

onUnmounted(() => {
  if (ws != null) {
    ws.close()
  }
});
</script>

<style scoped>
.v-container {
  height: 100vh;
}

.v-card {
  width: 100%;
}

.v-data-table {
  width: 100%;
}
</style>
