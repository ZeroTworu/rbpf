import { createStore } from "vuex";
import { logs, LogsState } from "./modules/logs";
import { rules, RulesState } from "./modules/rules";

export interface RootState {
    logs: LogsState;
    rules: RulesState;
}

const store = createStore<RootState>({
    modules: {
        logs,
        rules,
    },
});

export default store;
