<template>
  <v-dialog v-model="dialog" max-width="600px">
    <v-card>
      <v-btn
          icon
          color="red"
          size="16"
          class="close-btn"
          @click="$emit('close')"
      >
        <v-icon size="16`">mdi-close</v-icon>
      </v-btn>
      <v-card-title class="pa-4">
        <span>{{ localRule.rule_id ? "Редактировать правило" : "Добавить правило" }}</span>
      </v-card-title>
      <v-card-text>
        <v-row>
          <v-col cols="9">
            <v-text-field v-model="localRule.name" label="Имя правила"/>
          </v-col>
          <v-col cols="3">
            <v-checkbox v-model="localRule.on" label="Активно"/>
          </v-col>
        </v-row>
        <v-row>
          <v-col cols="6">
            <v-switch v-model="localRule.v4" label="IPv4"/>
          </v-col>
          <v-col cols="6">
            <v-switch v-model="localRule.v6" label="IPv6"/>
          </v-col>
        </v-row>
        <v-row>
          <v-col cols="6">
            <v-text-field
                v-if="localRule.v4"
                v-model="sourceAddrV4"
                label="Источник IPv4"
                :error-messages="ipv4SourceError"
            />
          </v-col>
          <v-col cols="6">
            <v-text-field
                v-if="localRule.v4"
                v-model="destinationAddrV4"
                label="Назначение IPv4"
                :error-messages="ipv4DestinationError"
            />
          </v-col>
        </v-row>
        <v-row>
          <v-col cols="6">
            <v-text-field v-if="localRule.v6" v-model="ipv6Source" label="Источник IPv6"/>
          </v-col>
          <v-col cols="6">
            <v-text-field v-if="localRule.v6" v-model="ipv6Destination" label="Назначение IPv6"/>
          </v-col>
        </v-row>
        <v-row>
          <v-col cols="6">
            <v-text-field v-model.number="localRule.source_port_start" label="Источник порт (начало)"/>
          </v-col>
          <v-col cols="6">
            <v-text-field v-model.number="localRule.source_port_end" label="Источник порт (конец)"/>
          </v-col>
        </v-row>
        <v-row>
          <v-col cols="6">
            <v-text-field v-model.number="localRule.destination_port_start" label="Назначение порт (начало)"/>
          </v-col>
          <v-col cols="6">
            <v-text-field v-model.number="localRule.destination_port_end" label="Назначение порт (конец)"/>
          </v-col>
        </v-row>

        <v-row>
          <v-col cols="6">
            <v-switch v-model="localRule.tcp" label="TCP"/>
          </v-col>
          <v-col cols="6">
            <v-switch v-model="localRule.udp" label="UDP"/>
          </v-col>
          <v-col cols="6">
            <v-switch v-model="localRule.drop" label="Блокировать"/>
          </v-col>
          <v-col cols="6">
            <v-switch v-model="localRule.ok" label="Пропускать"/>
          </v-col>

          <v-col cols="6">
            <v-switch v-model="localRule.input" label="IN"/>
          </v-col>
          <v-col cols="6">
            <v-switch v-model="localRule.output" label="OUT"/>
          </v-col>
        </v-row>
      </v-card-text>
      <v-card-actions>
        <v-btn color="primary" @click="save">Сохранить</v-btn>
        <v-btn color="secondary" @click="$emit('close')">Отмена</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import {computed, ref, watch} from "vue";

const props = defineProps({
  modelValue: Boolean,
  rule: Object,
});
const emit = defineEmits(["update:modelValue", "save", "close"]);

const dialog = computed({
  get: () => {
    console.log("RuleDialog.dialog.computed", props.rule);
    return props.modelValue;
  },
  set: (value) => emit("update:modelValue", value),
});

const ipv4SourceError = ref("");
const ipv4DestinationError = ref("");

const localRule = ref({...props.rule});

watch(() => props.rule, (newRule) => {
  localRule.value = {...newRule};
}, {immediate: true});

const validateIPv4 = (ip: string) => {
  const regex = /^(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$/;
  return regex.test(ip);
};

const ipToUint32 = (ip: string) => {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + Number(octet), 0);
};

const uint32ToIp = (num: number) => {
  return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join(".");
};


const sourceAddrV4 = computed({
  get: () => uint32ToIp(localRule.value.source_addr_v4 || 0),
  set: (value) => {
    if (validateIPv4(value)) {
      ipv4SourceError.value = "";
      localRule.value.source_addr_v4 = ipToUint32(value);
    } else {
      ipv4SourceError.value = "Неверный формат IPv4";
    }
  },
});

const destinationAddrV4 = computed({
  get: () => uint32ToIp(localRule.value.destination_addr_v4 || 0),
  set: (value) => {
    if (validateIPv4(value)) {
      ipv4DestinationError.value = "";
      localRule.value.destination_addr_v4 = ipToUint32(value);
    } else {
      ipv4DestinationError.value = "Неверный формат IPv4";
    }
  },
});

const ipv6Source = computed({
  get: () => `${
      (localRule.value.src_ip_high >>> 16).toString(16)}:${(localRule.value.src_ip_high & 0xFFFF).toString(16)}:${(localRule.value.src_ip_low >>> 16).toString(16)}:${(localRule.value.src_ip_low & 0xFFFF).toString(16)}`,
  set: (value) => {
    const parts = value.split(":").map((part) => parseInt(part, 16) || 0);
    localRule.value.src_ip_high = (parts[0] << 16) | parts[1];
    localRule.value.src_ip_low = (parts[2] << 16) | parts[3];
  },
});


const ipv6Destination = computed({
  get: () => `${(localRule.value.dst_ip_high >>> 16).toString(16)}:${(localRule.value.dst_ip_high & 0xFFFF).toString(16)}:${(localRule.value.dst_ip_low >>> 16).toString(16)}:${(localRule.value.dst_ip_low & 0xFFFF).toString(16)}`,
  set: (value) => {
    const parts = value.split(":").map((part) => parseInt(part, 16) || 0);
    localRule.value.dst_ip_high = (parts[0] << 16) | parts[1];
    localRule.value.dst_ip_low = (parts[2] << 16) | parts[3];
  },
});

const save = () => {
  emit("save", localRule.value);
  emit("close");
};
</script>
<style scoped>
.close-btn {
  position: absolute;
  top: 8px;
  right: 8px;
  z-index: 10;
}
</style>

