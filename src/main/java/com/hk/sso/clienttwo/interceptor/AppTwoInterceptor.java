package com.hk.sso.clienttwo.interceptor;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

public class AppTwoInterceptor extends HandlerInterceptorAdapter {
	


	private static Logger log = LoggerFactory.getLogger(AppTwoInterceptor.class);

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		// your code
		System.out.println("In the preHandler");
		//log.info("[preHandle][" + request + "]" + "[" + request.getMethod() + "]" + request.getRequestURI() + getParameters(request));
		boolean isValid = validateAuthorizationToken(request, response);
		System.out.println("Valid Token Available :: " + isValid);
		if(isValid) {
			/*if(!userHasSecAuthCookie(request)) 
	    	{*/
			setCookiesInSession(request, response);
			/*}else {
	    		// do nothing
	    	}*/
		}else {
			redirectToSSOApplication(request,response);
			// redirect to login page
			//String redirectUrl="http://localhost:8888/index";

		}

		return true;
	}

	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, 
			Object handler, ModelAndView modelAndView) throws Exception 
	{
		// your code
		log.info("[postHandle][" + request + "]");
	}


	@Override
	public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
		// your code
		if (ex != null){
			ex.printStackTrace();
		}
		log.info("[afterCompletion][" + request + "][exception: " + ex + "]");
	}

	private String getParameters(HttpServletRequest request) {
		StringBuffer posted = new StringBuffer();
		Enumeration<?> e = request.getParameterNames();
		if (e != null) {
			posted.append("?");
		}
		while (e.hasMoreElements()) {
			if (posted.length() > 1) {
				posted.append("&");
			}
			String curr = (String) e.nextElement();
			posted.append(curr + "=");
			if (curr.contains("password") 
					|| curr.contains("pass")
					|| curr.contains("pwd")) {
				posted.append("*****");
			} else {
				posted.append(request.getParameter(curr));
			}
		}
		String ip = request.getHeader("X-FORWARDED-FOR");
		String ipAddr = (ip == null) ? getRemoteAddr(request) : ip;
		if (ipAddr!=null && !ipAddr.equals("")) {
			posted.append("&_psip=" + ipAddr); 
		}
		return posted.toString();
	}

	private String getRemoteAddr(HttpServletRequest request) {
		String ipFromHeader = request.getHeader("X-FORWARDED-FOR");
		if (ipFromHeader != null && ipFromHeader.length() > 0) {
			log.debug("ip from proxy - X-FORWARDED-FOR : " + ipFromHeader);
			return ipFromHeader;
		}
		return request.getRemoteAddr();
	}

	private boolean validateAuthorizationToken(HttpServletRequest request, HttpServletResponse response) 
	{
		System.out.println("validateAuthorizationToken Enter");
		System.out.println("validateAuthorizationToken query string :: " + request.getQueryString() + " : " + request.getRequestURI());
		boolean securedTokenAvailableAndValid = false;
		try {

			boolean hasAuthTokenInCookie = userHasSecAuthCookie(request);

			if(hasAuthTokenInCookie) 
			{
				String tokenInCookie = getAuthTokenFromCookies(request);
				//check if its still valid
				securedTokenAvailableAndValid = isTokenStillValid(tokenInCookie);
				if(!securedTokenAvailableAndValid) 
				{
					String securedToken = request.getParameter("securedAuthToken");
					if(securedToken != null && !(tokenInCookie.equals(securedToken))) 
					{
						//setCookiesInSession(request, response);
						securedTokenAvailableAndValid = true;
					}else {
						securedTokenAvailableAndValid = false;
					}
				}
			}else {
				String securedToken = request.getParameter("securedAuthToken");
				System.out.println("validateAuthorizationToken securedToken :: " + securedToken);

				if(securedToken != null) {
					securedTokenAvailableAndValid = true;
					System.out.println("Secured Token is present");
				}
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("validateAuthorizationToken securedTokenAvailableAndValid :: " + securedTokenAvailableAndValid);
		return securedTokenAvailableAndValid;
	}

	private boolean userHasSecAuthCookie(HttpServletRequest request)
	{
		boolean hasSecuredAuthToken = false;
		Cookie[] cookies = request.getCookies();

		if (cookies != null) {
			for (Cookie cookie : cookies) 
			{
				if (cookie.getName().equals("securedAuthToken")) 
				{
					hasSecuredAuthToken = true;
					break;
				}
			}
		}
		System.out.println("userHasSecAuthCookie :: " + hasSecuredAuthToken);
		return hasSecuredAuthToken;
	}

	private String getAuthTokenFromCookies(HttpServletRequest request) {
		String authToken = null;
		Cookie[] cookies = request.getCookies();

		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("securedAuthToken")) {
					authToken = cookie.getValue();
				}
			}
		}
		System.out.println("get authToken from cookie :: " + authToken);
		return authToken;
	}

	public boolean isTokenStillValid(String jwt) {
		//This line will throw an exception if it is not a signed JWS (as expected)
		boolean decodeSuccess = false;
		try {
			String SECRET_KEY = "Opus#Pswd09";
			Claims claims = Jwts.parser()
					.setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
					.parseClaimsJws(jwt).getBody();
			decodeSuccess = true;
			System.out.println("get decodeSuccess :: " + decodeSuccess);
		} catch (ExpiredJwtException e) {
			e.printStackTrace();
		} catch (UnsupportedJwtException e) {
			e.printStackTrace();
		} catch (MalformedJwtException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		}
		return decodeSuccess;
	}
	/*public boolean isTokenValid(Claims claims) {

		System.out.println("Id :: " + claims.getId() + " Subject :: " + claims.getSubject() + " Issuer :: " + claims.getIssuer());
		System.out.println("Expiration  :: " + claims.getExpiration().getMinutes() );
		if(claims.getExpiration().after(new Date(System.currentTimeMillis())))
		{
			return true;
		}else {
			return false;
		}
	}*/

	private void redirectToSSOApplication(HttpServletRequest request, HttpServletResponse response)
	{
		String redirectUrl = getRedirectUrl(request);
		//response.encodeRedirectURL("redirectUrl");
		response.setStatus(HttpServletResponse.SC_TEMPORARY_REDIRECT);
		try {
			response.sendRedirect(redirectUrl);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		response.setHeader("Location", redirectUrl);
	}

	public String getRedirectUrl(HttpServletRequest request) {
		String redirectUrl="http://<ssoservername>:8090/sso/redirectlogin?client_id=ssoclient&subject=hk127b&return_url=<applicationservername>:8080/opus/home";
		return redirectUrl;
	}

	public void setCookiesInSession(HttpServletRequest request, HttpServletResponse response) 
	{
		Cookie cookie = new Cookie("securedAuthToken", request.getParameter("securedAuthToken"));
		String domainName = request.getServerName();
		System.out.println("domainName  :: " + domainName);
		String domainNamePrefix = domainName.substring(domainName.indexOf("."), domainName.length());
		System.out.println(domainName + " :: " + domainNamePrefix);
		cookie.setDomain(domainNamePrefix);
		//cookie.setDomain("<servername>");
		cookie.setHttpOnly(true);
		cookie.setPath("/");
		response.addCookie(cookie);
	}




}
