<script>
  import Login from './login.svelte'
  import Logout from './logout.svelte'

  import { user } from './stores.js';
  import { Router, Route, Link } from "svelte-routing";
  import Home from "./routes/home.svelte";

  export let url = "";
</script>

<Router url="{url}">
  <nav>
    <Link to="/">Home</Link>
    <Link to="login">Login</Link>
    <Link to="logout">Logout</Link>
  </nav>
  <div>
    <Route path="/" component="{Home}" />
    <Route path="login" component="{Login}" />
    <Route path="logout" component="{Logout}" />
    <!-- <Route path="blog/:id" component="{BlogPost}" /> -->
  </div>
</Router>
