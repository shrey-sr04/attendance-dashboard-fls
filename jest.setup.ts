import '@testing-library/jest-dom';
import { vi } from 'vitest';
import { cleanup } from '@testing-library/react';

// Clean up after each test
afterEach(() => {
    cleanup();
});

const mockStorage = new Map();

const localStorageMock = {
    getItem: (key: string) => mockStorage.get(key) || null,
    setItem: (key: string, value: string) => mockStorage.set(key, value),
    clear: () => mockStorage.clear(),
    removeItem: (key: string) => mockStorage.delete(key),
    length: mockStorage.size,
    key: (index: number) => Array.from(mockStorage.keys())[index],
};

Object.defineProperty(window, 'localStorage', {
    value: localStorageMock,
});

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation(query => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
    })),
});

// Mock ResizeObserver
global.ResizeObserver = class ResizeObserver {
    observe = vi.fn();
    unobserve = vi.fn();
    disconnect = vi.fn();
};

// Mock IntersectionObserver
global.IntersectionObserver = class IntersectionObserver {
    root: Element | null = null;
    rootMargin: string = '';
    thresholds: ReadonlyArray<number> = [];

    constructor(
        public callback: IntersectionObserverCallback,
        public options?: IntersectionObserverInit
    ) { }

    observe = vi.fn();
    unobserve = vi.fn();
    disconnect = vi.fn();
    takeRecords = vi.fn(() => []);
};


// Mock requestAnimationFrame
global.requestAnimationFrame = (callback) => setTimeout(callback, 0);
global.cancelAnimationFrame = vi.fn();