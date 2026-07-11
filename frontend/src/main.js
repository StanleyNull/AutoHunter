import { createApp } from "vue";
import { createRouter, createWebHashHistory } from "vue-router";
import App from "./App.vue";
import TasksView from "./views/TasksView.vue";
import CreateView from "./views/CreateView.vue";
import BoardView from "./views/BoardView.vue";
import SettingsView from "./views/SettingsView.vue";
import HardTargetsView from "./views/HardTargetsView.vue";
import IntelView from "./views/IntelView.vue";
import KnowledgeView from "./views/KnowledgeView.vue";
import VulnsView from "./views/VulnsView.vue";
import RuntimeLogsView from "./views/RuntimeLogsView.vue";
import { authReadyRef, authRoleRef, loadAuthRole } from "./api.js";
import "./style.css";

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", component: TasksView },
    { path: "/create", component: CreateView },
    { path: "/hard-targets", component: HardTargetsView },
    { path: "/intel", component: IntelView },
    { path: "/knowledge", component: KnowledgeView },
    { path: "/vulns", component: VulnsView },
    { path: "/runtime-logs", component: RuntimeLogsView },
    { path: "/settings", component: SettingsView },
    { path: "/task/:id", component: BoardView, props: true },
  ],
});

router.beforeEach(async (to) => {
  if (!authReadyRef.value) await loadAuthRole();
  if (authRoleRef.value === "observer" && ["/create", "/settings", "/intel", "/knowledge", "/vulns", "/runtime-logs"].includes(to.path)) {
    return "/";
  }
  return true;
});

createApp(App).use(router).mount("#app");
