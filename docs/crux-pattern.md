# Crux Pattern in Kameo Actors

This document describes how we applied Crux pattern's "separate intent from execution" to our Kameo actors for better testability.

## Architecture

Each actor now has three distinct parts:

### 1. Logic Module (Pure Functions)
- **Location**: `actors/xxx_actor.rs::logic`
- **Purpose**: Business logic, validation, planning
- **Characteristics**: No side effects, deterministic, fast to test
- **Tests**: `tests/unit/xxx_actor_tests.rs`

### 2. Effects Module (Side Effects)
- **Location**: `actors/xxx_actor.rs::effects`
- **Purpose**: All I/O operations (git, database, network)
- **Characteristics**: Only side effects, no business logic
- **Tests**: `tests/effects/xxx_actor_effects_tests.rs`

### 3. Message Handler (Orchestration)
- **Location**: `impl Message<...> for XxxActor`
- **Purpose**: Coordinate logic planning + effect execution
- **Characteristics**: Minimal, just glue code

## Testing Strategy

- **Unit Tests**: Test pure logic functions (microseconds)
- **Effect Tests**: Test side effects in isolation (milliseconds)
- **Integration Tests**: Test end-to-end behavior (seconds)

## Performance Improvements

- **Unit tests**: 10-100x faster than integration tests
- **Development cycle**: Faster feedback
- **CI/CD**: Quicker test runs