<?php

namespace Laraturka\Acl\Models;

use Illuminate\Database\Eloquent\Model;

class AclController extends Model
{
    public function group(){
        return $this->belongsTo('AclGroup');
    }
}