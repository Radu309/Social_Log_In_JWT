import './App.css';
import {useEffect} from "react";
import LoginButton from "./components/login";
import LogoutButton from "./components/logout";

const clientId = "218049732892-biibgbig5rri4nrgm4v9kelj0fff8nkv.apps.googleusercontent.com";

function App() {

  return (
    <div className="App">
      <LoginButton />
      <LogoutButton />
    </div>
  );
}

export default App;
