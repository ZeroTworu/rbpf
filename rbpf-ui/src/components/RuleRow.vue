<template>
  <tr>
    <td><strong>{{ rule.name }}</strong></td>
    <td @click="openIpModal('source')">{{ formatIpPort(rule, true) }}</td>
    <td @click="openIpModal('destination')">{{ formatIpPort(rule, false) }}</td>
      <td @click.stop>
        <v-select
            v-model="selectedProtocols"
            :items="protocolOptions"
            multiple
            chips
            label="Протокол"
            item-title="text"
            item-value="value"
            rounded="xl"
            variant="outlined"
            @blur="closeSelect('protocols')"
            @keydown.esc="closeSelect('protocols')"
            @update:modelValue="updateProtocolType"
        ></v-select>
      </td>

      <td @click.stop>
        <v-select
            v-model="selectedVersions"
            :items="versionOptions"
            multiple
            chips
            label="Версия"
            item-title="text"
            item-value="value"
            rounded="xl"
            variant="outlined"
            @blur="closeSelect('versions')"
            @keydown.esc="closeSelect('versions')"
            @update:modelValue="updateProtocolVersion"
        ></v-select>
      </td>

      <td @click.stop>
        <v-select
            v-model="selectedTraffic"
            :items="trafficOptions"
            multiple
            chips
            label="Тип трафика"
            item-title="text"
            item-value="value"
            rounded=""
            variant="outlined"
            @blur="closeSelect('traffic')"
            @keydown.esc="closeSelect('traffic')"
            @update:modelValue="updateTrafficType"
        ></v-select>
      </td>
    <td>
      <v-icon :color="rule.drop && !rule.ok ? 'red' : 'green'" @click="$emit('switchDrop', rule)">
        {{ rule.drop && !rule.ok ? 'mdi-close-circle' : 'mdi-check-circle' }}
      </v-icon>
    </td>
    <td>
      <v-switch v-model="rule.on" @click="$emit('switchOn', rule)"></v-switch>
    </td>
    <td>
      <v-icon @click="$emit('edit', rule)">mdi-pencil</v-icon>
    </td>
  </tr>

</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useStore } from 'vuex';
import ipaddr from "ipaddr.js";

import { ProtocolType, ProtocolVersionType, TrafficType } from '@/store/modules/rules';
defineEmits(['edit', 'switchOn', 'switchDrop']);
const props = defineProps({ rule: Object });

const formatIpPort = (rule, isSrc: boolean) => {
  if (isSrc){
    let ip = "";
    if  (rule.v4 && !isSrc) {
      ip = `${formatIpV4(rule.destination_addr_v4, rule.destination_mask_v4)}`
    }
    if  (rule.v4 && isSrc) {
      ip = `${formatIpV4(rule.source_addr_v4, rule.source_mask_v4)}`
    }
    if (rule.v6 && !isSrc) {
      ip = `${ip}  ${formatIpV6(rule.dst_ip_high, rule.dst_ip_low, rule.destination_mask_v6)}`
    }
    if (rule.v6 && isSrc) {
      ip = `${ip}  ${formatIpV6(rule.scr_ip_high, rule.scr_ip_low, rule.source_mask_v6)}`
    }
    return rule.destination_port_start === rule.destination_port_end ? `${ip}` : `${ip}:${rule.destination_port_start}-${rule.destination_port_end}`;
  }
  let ip = "";
  if  (rule.v4) {
        ip = `${formatIpV4(rule.destination_addr_v4, rule. destination_mask_v4)}`
  }
  if (rule.v6) {
    ip = `${ip}  ${formatIpV6(rule.dst_ip_high, rule.dst_ip_low, rule.destination_mask_v6)}`
  }
  return rule.destination_port_start === rule.destination_port_end ? `${ip}` : `${ip}:${rule.destination_port_start}-${rule.destination_port_end}`;
};

const formatIpV6 = (high: number, low: number, mask: number) => {
  const bytes = [
    (high >> 24) & 0xFF, (high >> 16) & 0xFF, (high >> 8) & 0xFF, high & 0xFF,
    (low >> 24) & 0xFF, (low >> 16) & 0xFF, (low >> 8) & 0xFF, low & 0xFF,
    0, 0, 0, 0, 0, 0, 0, 0  // добавляем нули, чтобы получить 16 байтов
  ];
  const ip = ipaddr.fromByteArray(bytes);
  if (mask !== 0) {
    return `${ip.toNormalizedString()}/${mask}`
    }
  return ip.toNormalizedString()
};
const formatIpV4 = (ip: number, mask: number) => {
  const ipv4 = ipaddr.fromByteArray([(ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF]);
  if (mask !== 0) {
    return `${ipv4.toString()}/${mask}`
  }
  return ipv4.toString()
};

const store = useStore();

// Опции для select
const protocolOptions = [
  { text: 'TCP', value: ProtocolType.TCP },
  { text: 'UDP', value: ProtocolType.UDP }
];

const versionOptions = [
  { text: 'IPv4', value: ProtocolVersionType.V4 },
  { text: 'IPv6', value: ProtocolVersionType.V6 }
];

const trafficOptions = [
  { text: 'IN', value: TrafficType.Input },
  { text: 'OUT', value: TrafficType.Output }
];

// Выбранные значения
const selectedProtocols = ref([
  ...(props.rule.tcp ? [ProtocolType.TCP] : []),
  ...(props.rule.udp ? [ProtocolType.UDP] : [])
]);

const selectedVersions = ref([
  ...(props.rule.v4 ? [ProtocolVersionType.V4] : []),
  ...(props.rule.v6 ? [ProtocolVersionType.V6] : [])
]);

const selectedTraffic = ref([
  ...(props.rule.input ? [TrafficType.Input] : []),
  ...(props.rule.output ? [TrafficType.Output] : [])
]);

// Обновление значений в объекте rule
const updateProtocolType = () => {
  props.rule.tcp = selectedProtocols.value.includes(ProtocolType.TCP);
  props.rule.udp = selectedProtocols.value.includes(ProtocolType.UDP);
  store.dispatch('rules/updateRule', props.rule);
};

const updateProtocolVersion = () => {
  props.rule.v4 = selectedVersions.value.includes(ProtocolVersionType.V4);
  props.rule.v6 = selectedVersions.value.includes(ProtocolVersionType.V6);
  store.dispatch('rules/updateRule', props.rule);
};

const updateTrafficType = () => {
  props.rule.input = selectedTraffic.value.includes(TrafficType.Input);
  props.rule.output = selectedTraffic.value.includes(TrafficType.Output);
  store.dispatch('rules/updateRule', props.rule);

};

const closeSelect = (type: string) => {
  switch (type) {
    case 'protocols':
          selectedProtocols.value = [...selectedProtocols.value];
          break;
    case 'versions':
          selectedVersions.value = [...selectedVersions.value]
          break
    case 'traffic':
          selectedTraffic.value = [...selectedTraffic.value]
          break;
  }
};

</script>

<style scoped>
tr { cursor: default; }
.v-icon, .v-switch { cursor: pointer; }
</style>