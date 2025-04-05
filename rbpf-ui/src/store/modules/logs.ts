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
    ws: WebSocket | null,
}

const state: LogsState = {
    logs: [],
    ws: null as WebSocket | null,
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
    SET_WS(state: LogsState, ws: WebSocket) {
        state.ws = ws;
    },
};

const actions = {
    addLog({ commit }, log: LogMessage) {
        commit("ADD_LOG", log);
    },
    clearLogs({ commit }) {
        commit("CLEAR_LOGS");
    },
    connectWebSocket({ commit, dispatch, state }: any) {
        if (state.ws) return; // не подключаться повторно

        const ws = new WebSocket(import.meta.env.VITE_WS_LOGS_URL);

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                dispatch("addLog", data);
            } catch (error) {
                console.error("ws.onmessage.ERROR:", error);
            }
        };

        ws.onerror = (error) => console.error("ws.onerror:", error);

        ws.onclose = () => {
            commit("SET_WS", null);
            setTimeout(() => dispatch("connectWebSocket"), 5000);
        };

        commit("SET_WS", ws);
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
