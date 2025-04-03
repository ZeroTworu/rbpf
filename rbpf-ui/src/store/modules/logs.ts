import { Module } from "vuex";
import type { RootState } from "@/store"; //

export interface LogMessage {
    traffic_type: string;
    protocol_version_type: string;
    protocol_type: string;
    source_addr_v6: string;
    destination_addr_v6: string;
    source_addr_v4: string;
    destination_addr_v4: string;
    if_name: string;
    rule_name: string;
    source_port: string;
    destination_port: string;
    action: string;
}

export interface LogsState {
    logs: LogMessage[];
}

const state: LogsState = {
    logs: [],
};

const mutations = {
    ADD_LOG(state: LogsState, log: LogMessage) {
        state.logs.unshift(log);
        if (state.logs.length > 100) {
            state.logs.pop(); // Ограничиваем до 100 записей
        }
    },
    CLEAR_LOGS(state: LogsState) {
        state.logs = [];
    },
};

const actions = {
    addLog({ commit }, log: LogMessage) {
        commit("ADD_LOG", log);
    },
    clearLogs({ commit }) {
        commit("CLEAR_LOGS");
    },
};

const getters = {
    logs: (state: LogsState) => state.logs,
};

export const logs: Module<LogsState, RootState> = {
    namespaced: true,
    state,
    mutations,
    actions,
    getters,
};
