import {createStore} from "vuex";

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

export interface State {
    logs: LogMessage[];
}

export default createStore<State>({
    state: {
        logs: [] as LogMessage[],
    },
    mutations: {
        ADD_LOG(state: State, log: LogMessage) {
            state.logs.unshift(log);
        },
        CLEAR_LOGS(state: State) {
            state.logs = [];
        },
    },
    actions: {
        addLog({ commit }, log: LogMessage) {
            commit("ADD_LOG", log);
        },
        clearLogs({ commit }) {
            commit("CLEAR_LOGS");
        },
    },
    getters: {
        logs: (state: State) => state.logs,
    },
});
