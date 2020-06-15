<script>
  import Login from './login.svelte'
  import Logout from './logout.svelte'

  import { user } from './stores.js';
</script>

{#if !$user.authToken}
  <Login/>
{:else}
  <Logout/>
{/if}
