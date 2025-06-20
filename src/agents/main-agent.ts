import { state, log, on } from './module';

on('init', () => {
    log("Script Loaded", state);
})
