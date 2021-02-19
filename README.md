# node-naver
naver login

## example
```ts
import { Naver, NaverCookies } from './naver';
new Naver('ID', 'PASSWORD').login()
    .then(res => console.log(res.getCookies()))
    .catch(e => console.log(e));
```
