import "./app.css";
import { mount } from "svelte";
import App from "./App.svelte";
import { start } from "./lib/store.svelte";

mount(App, { target: document.getElementById("app")! });
start();
