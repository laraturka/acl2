<?php


namespace Laraturka\Acl;
use Illuminate\Support\Facades\DB;

trait AclHasGate
{

    public function hasGroup($group)
    {

        if (is_string($group)) {
            return $this->Groups->contains('name', $group);
        }

        //check if exists mached user grous and gate groups
        return !! $group->intersect($this->groups)->count();
    }

    public function hasGate($gate)
    {
        return $this->checkIfGateAuthorized($gate);
    }

    public function checkIfGateAuthorized($gate){
        if (!auth()->check()) return false;
        $site_id = Acl::$site_id;

        //gate name is null means wildcard allowed
        $count = DB::table('users')
            ->select('acl_gates.*')
            ->join('user_acl_group_site',function($join) use($site_id){
                $join->on('user_acl_group_site.user_id','=','users.id')->where(function ($q)use($site_id){$q->where('user_acl_group_site.site_id','=',$site_id)->orWhereNull('user_acl_group_site.site_id');});
            })
            ->join('acl_groups', 'acl_groups.id', '=', 'user_acl_group_site.acl_group_id')
            ->join('acl_gates', 'acl_gates.acl_group_id', '=', 'acl_groups.id')
            ->where('users.id', '=', auth()->user()->id  )
            ->where(function ($q) use($gate) { //Check if name is null or equal
                $q->whereNull('acl_gates.name')
                    ->orWhere('acl_gates.name', $gate);
            })
            ->count();

        return $count>0;
    }

}
