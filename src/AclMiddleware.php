<?php

namespace Laraturka\Acl;

use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class AclMiddleware
{

    public function __construct(AuthManager $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {

        //Check if domain
        $site = DB::table('site')->select(['site.id'])->where('domain',$request->server("HTTP_HOST"))->where('status','>=',0)->first();
        if (is_null($site))
            abort(404);

        Acl::$site_id = $site->id;

        //Get route
        $route = app()->router->getRoutes()->match($request);

        //Get uses from route
        $uses = $route->getAction()['uses'];

        //Check if uses is string or not
        if (!is_string($uses)) return $next($request);

        //Explode controller and method from uses.
        list($controller, $method) = explode('@', str_replace('App\Http\Controllers\\', "", $uses));

        //Void if Auth
        if (substr_count($controller, 'Auth\\') > 0) return $next($request);

        //Force login if not logged in.
        if (!auth()->check()) return $next($request);

        //Check if authorized controller and method
        if (!$this->checkIfAuthorized($controller, $method,$site->id))
            abort(401, 'Unauthorized.');

        //Continue from next onion level
        return $next($request);
    }

    protected function checkIfAuthorized($controller, $method,$site_id = null)
    {

        if (!auth()->check()) return false;

        //Controller or method is null means wildcard allowed
        $count = DB::table('users')
            ->join('user_acl_group_site',function($join) use($site_id){
                $join->on('user_acl_group_site.user_id','=','users.id')->where(function ($q)use($site_id){$q->where('user_acl_group_site.site_id','=',$site_id)->orWhereNull('user_acl_group_site.site_id');});
            })
            ->join('acl_groups', 'acl_groups.id', '=', 'user_acl_group_site.acl_group_id')
            ->join('acl_controllers', 'acl_controllers.acl_group_id', '=', 'user_acl_group_site.acl_group_id')
            ->select('acl_controllers.*')
            ->where('users.id', '=', auth()->user()->id)
            ->where(function ($q) use ($controller) { //Check if controller is null or equal
                $q->whereNull('acl_controllers.controller')
                    ->orWhere('acl_controllers.controller', $controller);
            })
            ->where(function ($q) use ($method) { //Check if controller is null or method is null or method is equal
                $q->whereNull('acl_controllers.controller')
                    ->orWhere(function ($q) use ($method) {
                        $q->whereNull('acl_controllers.method')
                            ->orWhere('acl_controllers.method', $method);
                    });
            })
            ->count();

        return $count > 0;
    }

    protected function forceLogin($request, $guard = null)
    {

        if (Auth::guard($guard)->guest()) {
            if ($request->ajax() || $request->wantsJson()) {
                return response('Unauthorized..', 401);
            } else {
                return redirect()->guest('login');
            }
        }
    }
}
