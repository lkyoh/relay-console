/** Reuse immutable branches so identical polling results do not invalidate consumers. */
export function shareSnapshot<T>(previous:T,next:T):T {
 if(Object.is(previous,next))return previous
 if(previous===null||next===null||typeof previous!=='object'||typeof next!=='object'||Array.isArray(previous)!==Array.isArray(next))return next
 const a=previous as Record<string,unknown>,b=next as Record<string,unknown>,keys=Object.keys(b)
 let equal=Object.keys(a).length===keys.length
 for(const key of keys){const shared=shareSnapshot(a[key],b[key]);b[key]=shared;if(!Object.hasOwn(a,key)||shared!==a[key])equal=false}
 return equal?previous:next
}
