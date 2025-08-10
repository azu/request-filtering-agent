// Custom loader to resolve .js imports to .ts files
export async function resolve(specifier, context, nextResolve) {
  // Only handle relative imports
  if (specifier.startsWith('.') || specifier.startsWith('/')) {
    // Replace .js with .ts for local imports
    if (specifier.endsWith('.js')) {
      specifier = specifier.slice(0, -3) + '.ts';
    }
  }
  return nextResolve(specifier, context);
}