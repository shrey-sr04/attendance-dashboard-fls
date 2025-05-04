import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
    plugins: [react()],
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: ['./tests/setup.ts'],
        include: ['**/*.test.{ts,tsx}'],
        exclude: ['**/node_modules/**', '**/dist/**'],
        alias: {
            '@': path.resolve(__dirname),
        },
    },
    resolve: {
        alias: {
            '@': path.resolve(__dirname),
        },
    },
})