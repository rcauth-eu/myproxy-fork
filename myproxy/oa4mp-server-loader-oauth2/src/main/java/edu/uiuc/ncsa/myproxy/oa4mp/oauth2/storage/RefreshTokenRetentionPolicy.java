package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/14 at  3:39 PM
 */
public class RefreshTokenRetentionPolicy implements RetentionPolicy {
    public RefreshTokenRetentionPolicy(RefreshTokenStore rts) {
        this.rts = rts;
    }

    RefreshTokenStore rts;

    /**
     * Always true for every element in the cache.
     *
     * @return
     */
    @Override
    public boolean applies() {
        return true;
    }

    @Override
    public boolean retain(Object key, Object value) {
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) value;
        RefreshToken rt = st2.getRefreshToken();
        long timeout = st2.getRefreshTokenLifetime();
        if (rt == null || rt.getToken() == null) {
            // fall back to looking at the access token timestamp. Failing that, fall back to the creation time from
            // the identifier.
            String  token;
            token = (st2.getAccessToken()==null?st2.getIdentifierString():st2.getAccessToken().getToken());
            try {
                DateUtils.checkTimestamp(token);
            } catch (InvalidTimestampException its) {
                return false;
            }
            return true;
        }
        // Now we have to check against the timestamp on the original and the expires in flag.
        /*
           try {
            // if there is no max timeout set, then use whatever the default is.
            if (maxTimeout <= 0) {
                DateUtils.checkTimestamp(key.toString());
            } else {
                DateUtils.checkTimestamp(key.toString(), maxTimeout);
            }
            return true;
        } catch (InvalidTimestampException its) {
            return false;
        }
         */
        try {
            if (timeout <= 0) {
                DateUtils.checkTimestamp(rt.getToken()); // use default????

            } else {
                DateUtils.checkTimestamp(rt.getToken(), timeout);
            }
            return true;
        } catch (InvalidTimestampException its) {
            return false;
        }
/*
        Date creationTS = DateUtils.getDate(st2.getRefreshToken().getToken());


        if (System.currentTimeMillis() < (creationTS.getTime() + st2.getRefreshTokenLifetime())) {
            return true;
        }
        return false;
*/
    }

    @Override
    public Map getMap() {
        return rts;
    }
}
