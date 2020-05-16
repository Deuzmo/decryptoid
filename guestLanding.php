<?php // guestLanding.php 

         echo <<<_END
         <h1 style = "text-align:center; font-style:italic"> Decryptoid </h2>
         <div style = "border-style:ridge; width:40%; padding:20px; margin: 0 auto; display: flex; flex-direction:row">
            <form style = "margin: 0 auto;" action="createUser.php" method="post" enctype='multipart/form-data'>
               <input type="submit" value="Create new user">
            </form>
            <form style = "margin: 0 auto;" action="authenticate.php" method="post" enctype='multipart/form-data'>
               <input type="submit" value="Log in as existing user">
            </form>
         </div>
_END;

?>
