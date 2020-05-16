<?php 		// authenticate.php
   require_once 'login.php';
   require_once 'interface.php';
   
   if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW']))
	{
      $tmpUser = sanitizeLogin($conn, "PHP_AUTH_USER");
      $tmpPw = sanitizeLogin($conn, "PHP_AUTH_PW");

      if (login($conn, $userTable, $tmpUser, $tmpPw)){

         // To avoid session fixation attack, session id is changed
         // on every succesful login.
         session_regenerate_id();
         echo "Hello $tmpUser, welcome back." .

         $_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'] .
                              $_SERVER['HTTP_USER_AGENT']);
         $_SESSION['username'] = $tmpUser;
  
         "<p><a href=userLanding.php> Click here to continue </a></p>";

      }
      else{ 

         die ("Invalid combination. <b><a href=guestLanding.php>Please click here</a></b>" . 
         " to log in or create a new account.");

      }
   }
   else {

      header('WWW-Authenticate: Basic realm="Restricted Section"');
      header('HTTP/1.0 401 Unauthorized');
      die ("Restricted section. <b><a href=guestLanding.php>Please click here</a></b>" . 
      " to log in or create a new account.");

   }
?>