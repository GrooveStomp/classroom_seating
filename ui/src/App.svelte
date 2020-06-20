<script>
  import Login from './login.svelte'
  import Logout from './logout.svelte'
  import Signup from './signup.svelte'

  import { user } from './stores.js';
</script>

<Signup/>
{#if !$user.authToken}
  <Login/>
{:else}
  <Logout/>
{/if}
