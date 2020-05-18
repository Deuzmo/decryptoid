<?php 		// authenticate.php
   require_once 'login.php';
   require_once 'interface.php';
   session_start();
   if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW']))
	{
      echo "<div style = \"border-style:ridge; width:40%; padding:20px; margin: 0 auto\">";
      $tmpUser = sanitizeLogin($conn, "PHP_AUTH_USER");
      $tmpPw = sanitizeLogin($conn, "PHP_AUTH_PW");
      
      if (login($conn, $userTable, $tmpUser, $tmpPw)){

         // To avoid session fixation attack, session id is changed
         // on every succesful login.
         session_regenerate_id();
         $_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'] .
                                                $_SERVER['HTTP_USER_AGENT']);
         $_SESSION['username'] = $tmpUser;

         echo "<h4> Hello $tmpUser! Welcome back. " .
              "<a href=userLanding.php>Click here to continue</a></h4>";

         $_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'] .
                              $_SERVER['HTTP_USER_AGENT']);
         $_SESSION['username'] = $tmpUser;


      }
      else{ 
         $conn->close();
         echo "<h4> Invalid combination. <a href=guestLanding.php>Please click here</a>" . 
         " to log in or create a new account.</h4>";

      }
      echo "</div>";
   }
   else {

      header('WWW-Authenticate: Basic realm="Restricted Section"');
      header('HTTP/1.0 401 Unauthorized');
      $conn->close();
      die ("Restricted section. <b><a href=guestLanding.php>Please click here</a></b>" . 
      " to log in or create a new account.");

   }
?>